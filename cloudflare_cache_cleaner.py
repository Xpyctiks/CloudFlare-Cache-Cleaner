#!/usr/bin/env python3

from flask import Flask,render_template,request,make_response,redirect,flash, session
import os, sys, logging, requests, httpx, string, random, asyncio, base64
from cryptography.fernet import Fernet
from datetime import timedelta, datetime
from flask_login import LoginManager,logout_user, login_required, current_user, UserMixin, login_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy

CONFIG_DIR = "/etc/cloudflare-cache-cleaner/"
DB_FILE = os.path.join(CONFIG_DIR,"cloudflare-cache-cleaner.db")
#key to ecnrypt API token in <hidden> filed to easy process of purge method
CF_ACCOUNTS = []
TELEGRAM_TOKEN = TELEGRAM_CHATID = LOG_FILE = ENCRYPT_KEY = ""
application = Flask(__name__)
application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.config['PERMANENT_SESSION_LIFETIME'] = 28800
application.config['SESSION_COOKIE_SECURE'] = False
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
application.config['SESSION_USE_SIGNER'] = True
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
db = SQLAlchemy()
db.init_app(application)
application.config['SESSION_SQLALCHEMY'] = db

class Accounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False, unique=True)
    token = db.Column(db.String(64), nullable=False, unique=True)
    created = db.Column(db.DateTime,default=datetime.now)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegramChat = db.Column(db.String(16), nullable=True)
    telegramToken = db.Column(db.String(64), nullable=True)
    logFile = db.Column(db.String(512), nullable=False)
    encryptKey = db.Column(db.String(64), nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    realname = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    rights = db.Column(db.String(), nullable=False, default="*")
    created = db.Column(db.DateTime,default=datetime.now)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

def load_config() -> None:
    """Important function - loads all configuration values from Sqlite3 database when an application starts"""
    generate_default_config()
    with application.app_context():
        try:
            config = db.session.get(Settings, 1)
            global TELEGRAM_TOKEN, TELEGRAM_CHATID, LOG_FILE, ENCRYPT_KEY, CF_ACCOUNTS
            TELEGRAM_TOKEN = config.telegramToken
            TELEGRAM_CHATID = config.telegramChat
            ENCRYPT_KEY = config.encryptKey
            LOG_FILE = config.logFile
            logging.basicConfig(filename=LOG_FILE,level=logging.DEBUG,format='%(asctime)s - Cloudflare-Cache-Cleaner - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
            CF_ACCOUNTS = [ {"Name": acc.name, "Token": acc.token} for acc in Accounts.query.all()]
        except Exception as msg:
            print(f"Load-config error: {msg}")
            quit(1)

def generate_default_config() -> None:
    """Checks every application loads if the app's configuration exists. If not - creates DB file with default values.Takes application as app context, CONFIG_DIR as value where config DB located and DB_FILE as config DB name"""
    with application.app_context():
        if not os.path.isfile(DB_FILE):
            length = 32
            characters = string.ascii_letters + string.digits
            session_key = ''.join(random.choice(characters) for _ in range(length))
            default_settings = Settings(id=1, 
                telegramChat = "",
                telegramToken = "",
                logFile = "/var/log/cloudflare-cache-cleaner.log",
                encryptKey = session_key,
                )
            try:
                if not os.path.exists(CONFIG_DIR):
                    os.mkdir(CONFIG_DIR)
                db.create_all()
                db.session.add(default_settings)
                db.session.commit()
                print(f"First launch. Default database created in {DB_FILE}. You need to add telegram ChatID and Token if you want to get notifications")
            except Exception as msg:
                print(f"Generate-default-config error: {msg}")
                quit(1)

def set_telegramChat(tgChat: str) -> None:
    """CLI only function: sets Telegram ChatID value in database"""
    t = Settings(id=1,telegramChat=tgChat.strip())
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram ChatID added successfully")
    try:
        logging.info(f"Telegram ChatID updated successfully!")
    except Exception as err:
        pass

def set_telegramToken(tgToken: str) -> None:
    """CLI only function: sets Telegram Token value in database"""
    t = Settings(id=1,telegramToken=tgToken)
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram Token added successfully")
    try:
        logging.info(f"Telegram Token updated successfully!")
    except Exception as err:
        pass

def set_logpath(logpath: str) -> None:
    """CLI only function: sets Logger file path value in database"""
    t = Settings(id=1,logFile=logpath)
    db.session.merge(t)
    db.session.commit()
    load_config()
    updated = db.session.get(Settings, 1)
    print(f"logPath updated successfully. New log path: \"{updated.logFile}\"")
    try:
        logging.info(f"logPath updated to \"{updated.logFile}\"")
    except Exception as err:
        pass

def register_user(username: str,password: str,realname: str) -> None:
    """CLI only function: adds new user and saves to database"""
    try:
        if User.query.filter_by(username=username).first():
            print(f"User \"{username}\" creation error - already exists!")
            logging.error(f"User \"{username}\" creation error - already exists!")
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                realname=realname,
            )
            db.session.add(new_user)
            db.session.commit()
            #load_config()
            print(f"New user \"{username}\" - \"{realname}\" created successfully!")
            logging.info(f"New user \"{username}\" - \"{realname}\" created successfully!")
    except Exception as err:
        logging.error(f"User \"{username}\" - \"{realname}\" creation error: {err}")
        print(f"User \"{username}\" - \"{realname}\" creation error: {err}")

def update_user(username: str,password: str) -> None:
    """CLI only function: password change for existing user"""
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            d = User(id=user.id,password_hash=generate_password_hash(password))
            db.session.merge(d)
            db.session.commit()
            print(f"Password for user \"{user.username}\" updated successfully!")
            logging.info(f"Password for user \"{user.username}\" updated successfully!")
        else:
            print(f"User \"{username}\" set password error - no such user!")
            logging.error(f"User \"{username}\" set password error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{username}\" set password error: {err}")
        print(f"User \"{username}\" set password error: {err}")

def delete_user(username: str) -> None:
    """CLI only function: deletes an existing user from database"""
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            load_config()
            print(f"User \"{user.username}\" deleted successfully!")
            logging.info(f"User \"{user.username}\" deleted successfully!")
        else:
            print(f"User \"{username}\" delete error - no such user!")
            logging.error(f"User \"{username}\" delete error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{username}\" delete error: {err}")
        print(f"User \"{username}\" delete error: {err}")

def add_cfaccount(name: str, token: str) -> None:
    """CLI only function: Adds new CF account and its token to the database"""
    try:
        if Accounts.query.filter_by(name=name).first():
            print(f"Account with name \"{name}\" already exists!")
            logging.error(f"Account with name \"{name}\" already exists!")
            quit(1)
        elif Accounts.query.filter_by(token=token).first():
            print(f"Account with token \"{token}\" already exists!")
            logging.error(f"Account with token \"{token}\" already exists!")
            quit(1)
        else:
            new_account = Accounts(
                name=name,
                token=token)
            db.session.add(new_account)
            db.session.commit()
            logging.info(f"Account \"{name}\" added successfully!")
            print(f"Account \"{name}\" added successfully!")
    except Exception as err:
        logging.error(f"Account \"{name}\" adding error: {err}")
        print(f"Account \"{name}\" adding error: {err}")

def delete_cfaccount(name: str) -> None:
    """CLI only function: deletes an existing account from the database"""
    try:
        acc = Accounts.query.filter_by(name=name).first()
        if acc:
            db.session.delete(acc)
            db.session.commit()
            load_config()
            print(f"User \"{acc.name}\" deleted successfully!")
            logging.info(f"User \"{acc.name}\" deleted successfully!")
        else:
            print(f"Account \"{name}\" delete error - no such account!")
            logging.error(f"Account \"{name}\" delete error - no such account!")
            quit(1)
    except Exception as err:
        logging.error(f"Account \"{name}\" delete error: {err}")
        print(f"Account \"{name}\" delete error: {err}")

def import_accounts(file):
    load_config()
    print(f"Starting bulk loading of account from file {file}")
    logging.info(f"Starting bulk loading of account from file {file}")
    data = []
    try:
        with open(file, 'r',encoding='utf8') as file2:
            for line in file2:
                stripped = line.strip()
                if not stripped:
                    continue
                parts = stripped.split(maxsplit=1)
                if len(parts) == 2:
                    name, token = parts
                    data.append({"name": name, "token": token})
                else:
                    print(f"Incorrect line skipped: {line}")
                if Accounts.query.filter_by(name=name).first():
                    print(f"Account with name \"{name}\" already exists!")
                    logging.error(f"Account with name \"{name}\" already exists!")
                    continue
                elif Accounts.query.filter_by(token=token).first():
                    print(f"Account with token \"{token}\" already exists!")
                    logging.error(f"Account with token \"{token}\" already exists!")
                    continue
                new_entry = Accounts(name=name, token=token)
                db.session.add(new_entry)
        db.session.commit()
        load_config()
        print(f"Bulk accounts loaded from file successfully.")
        logging.info(f"Bulk accounts loaded successfully from {file}.")
    except Exception as err:
        logging.error(f"Bulk accounts loading error: {err}")
        print(f"Bulk accounts loading error: {err}")

load_config()
application.secret_key = ENCRYPT_KEY
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.session_protection = "strong"
login_manager.init_app(application)
with application.app_context():
    db.create_all()

async def send_to_telegram(message: str, subject: str = "__name__", ) -> None:
    """Sends messages via Telegram if TELEGRAM_CHATID and TELEGRAM_TOKEN are both set. Requires "message" parameters and can accept "subject" """
    if TELEGRAM_CHATID and TELEGRAM_TOKEN:
        headers = {
            'Content-Type': 'application/json',
        }
        data = {
            "chat_id": f"{TELEGRAM_CHATID}",
            "text": f"{subject}\n{message}",
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.post(
                    f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                    headers=headers,
                    json=data
                )
            print(response.status_code)
            if response.status_code != 200:
                logging.error("error", f"Telegram bot error! Status: {response.status_code} Body: {response.text}")
        except Exception as err:
            logging.error(f"Error while sending message to Telegram: {err}")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))

#catch logout form. Deleting cookies and redirect to /
@application.route("/logout", methods=['POST'])
@login_required
def logout():
    logging.info(f"User {current_user.realname} is logging out")
    logout_user()
    session.clear()
    response = make_response(redirect("/login",301))
    response.delete_cookie('session')
    response.delete_cookie('remember_token')
    flash("You are logged out", "alert alert-info")
    return response

@application.route("/purge", methods=['POST'])
@login_required
def purge():
    if request.method == 'POST':
        key = base64.urlsafe_b64encode(ENCRYPT_KEY.encode().ljust(32, b'\0'))
        cipher = Fernet(key)
        token = cipher.decrypt(request.form['hash'].encode('utf-8')).decode('utf-8')
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type':  'application/json'
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{request.form['zoneid']}/purge_cache"
        response = requests.post(url, json={"purge_everything": True}, headers=headers)
        if response.status_code == 200:
            asyncio.run(send_to_telegram(f"🍀CloudFlare cache of {request.form['purge']} purged successfully by {current_user.realname}!"))
            logging.info(f"CloudFlare cache of {request.form['purge']} purged successfully by {current_user.realname}!")
            response = make_response(redirect("/"),301)
            flash(f"Cache of {request.form['purge']} purged successfully!", "alert alert-success")
            return response
        else:
            asyncio.run(send_to_telegram(f"💢Error purging CloudFlare cache for {request.form['purge']} by {current_user.realname}!"))
            logging.error(f"Error purging CloudFlare cache for {request.form['purge']} by {current_user.realname}!")
            response = make_response(redirect("/"),301)
            flash(f"{request.form['zoneid']} purge error!", "alert alert-danger")
            return response
    else:
        response = make_response(redirect("/"),301)
        return response

#catch login form. Check if user exists in the list and password is correct. If yes - set cookies and redirect to /
@application.route("/login", methods=['GET','POST'])
def login():
    if request.method == 'POST':
        if current_user.is_authenticated:
            logging.info(f"POST: User {current_user.username} IP:{request.remote_addr} is already logged in. Redirecting to the main page.")
            return redirect('/',301)
        username = request.form["username"]
        password = request.form["password"]        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session.permanent = True
            login_user(user, remember=True, duration=timedelta(hours=8))
            logging.info(f"User {user.realname} from IP:{request.remote_addr} logged in successfully")
            response = make_response(redirect("/",301))
            return response
        else:
            logging.error(f"Login: Wrong password \"{password}\" for user \"{username}\", IP:{request.remote_addr}")
            asyncio.run(send_to_telegram(f"🚷Login error.Wrong password for user \"{username}\", IP:{request.remote_addr}"))
            flash('Wrong username or password!', 'alert alert-danger')
            return render_template("template-login.html")    
    if current_user.is_authenticated:
        logging.info(f"not POST: User {current_user.username} IP:{request.remote_addr} is already logged in. Redirecting to the main page.")
        return redirect('/',301)
    else:
        return render_template("template-login.html")
 
@application.route("/", methods=['GET'])
@login_required
def index():
    try:
        table = ""
        id = 1
        nameserver1 = ""
        nameserver2 = ""
        #getting all permissions from current user as the list
        permissions_list = [item.strip() for item in current_user.rights.split(',')]
        for account in CF_ACCOUNTS:
            if account['Name'] in permissions_list or "*" in permissions_list:
                
                headers = {
                    'Authorization': f"Bearer {account['Token']}",
                    'Content-Type':  'application/json'
                }
                key = base64.urlsafe_b64encode(ENCRYPT_KEY.encode().ljust(32, b'\0'))
                cipher = Fernet(key)
                url = 'https://api.cloudflare.com/client/v4/zones'
                hash = cipher.encrypt(account['Token'].encode('utf-8')).decode('utf-8')
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    for i in response.json()["result"]:
                        if not 'name_servers' in i:
                            nameserver1 = "None"
                            nameserver2 = "None"
                        else:
                            nameserver1 = i['name_servers'][0]
                            nameserver2 = i['name_servers'][1]
                        if i['status'] != "active":
                            table += f"""\n<tr>\n<th scope="row" class="table-danger">{id}</th>
                            <td class="table-danger"><form method="post" action="/purge"><button type="submit" value="{i['name']}" name="purge" class="btn btn-primary">Purge Cache</button>
                            <input type="hidden" name="zoneid" value="{i['id']}">
                            <input type="hidden" name="hash" value="{hash}"></form></td>
                            <td class="table-danger">{i['name']}</td>
                            <td class="table-danger">{i['status']}</td>
                            <td class="table-danger">{nameserver1}, {nameserver2}</td>
                            <td class="table-danger">{i['account']['name']}</td>
                            <td class="table-danger">{i['id']}</td>
                            <td class="table-danger">{i['original_registrar']}</td>
                            <td class="table-danger">{i['plan']['name']}</td>\n</tr>"""
                        else:
                            table += f"""\n<tr>\n<th scope="row" class="table-success">{id}</th>
                            <td class="table-success"><form method="post" action="/purge"><button type="submit" value="{i['name']}" name="purge" onclick="showLoading()" class="btn btn-primary">Purge Cache</button>
                            <input type="hidden" name="zoneid" value="{i['id']}">
                            <input type="hidden" name="hash" value="{hash}"></form></td>
                            <td class="table-success">{i['name']}</td>
                            <td class="table-success">{i['status']}</td>
                            <td class="table-success">{nameserver1}, {nameserver2}</td>
                            <td class="table-success">{i['account']['name']}</td>
                            <td class="table-success">{i['id']}</td>
                            <td class="table-success">{i['original_registrar']}</td>
                            <td class="table-success">{i['plan']['name']}</td>\n</tr>"""
                        id += 1
                else:
                    print(f"Error:{response}")
                    logging.error(f"Error:{response}")
        return render_template("template-main.html",table=table)
    except Exception as msg:
        logging.error(f"Error in index(): {msg}")

if __name__ == "__main__":
    application.app_context().push()
    load_config()
    if len(sys.argv) > 2:
        if sys.argv[1] == "set" and sys.argv[2] == "chat":
            if (len(sys.argv) == 4):
                set_telegramChat(sys.argv[3].strip())
            else:
                print("Error! Enter ChatID")
        elif sys.argv[1] == "set" and sys.argv[2] == "token":
            if (len(sys.argv) == 4):
                set_telegramToken(sys.argv[3].strip())
            else:
                print("Error! Enter Token")
        elif sys.argv[1] == "set" and sys.argv[2] == "log":
            if (len(sys.argv) == 4):
                set_logpath(sys.argv[3].strip())
            else:
                print("Error! Enter log path")
        elif sys.argv[1] == "user" and sys.argv[2] == "add":
            if (len(sys.argv) == 6):
                register_user(sys.argv[3].strip(),sys.argv[4].strip(),sys.argv[5].strip())
            else:
                print("Error! Enter both username and password")
        elif sys.argv[1] == "user" and sys.argv[2] == "setpwd":
            if (len(sys.argv) == 5):
                update_user(sys.argv[3].strip(),sys.argv[4].strip())
            else:
                print("Error! Enter both username and new password")
        elif sys.argv[1] == "user" and sys.argv[2] == "del":
            if (len(sys.argv) == 4):
                delete_user(sys.argv[3].strip())
            else:
                print("Error! Enter both username and new password")
        elif sys.argv[1] == "account" and sys.argv[2] == "add":
            if (len(sys.argv) == 5):
                add_cfaccount(sys.argv[3].strip(),sys.argv[4].strip())
            else:
                print("Error! Enter both account's name and token")
        elif sys.argv[1] == "account" and sys.argv[2] == "del":
            if (len(sys.argv) == 4):
                delete_cfaccount(sys.argv[3].strip())
            else:
                print("Error! Enter account's name to delete")
        elif sys.argv[1] == "account" and sys.argv[2] == "import":
            if (len(sys.argv) == 4):
                import_accounts(sys.argv[3].strip())
            else:
                print("Error! Enter path to file with accounts list")
        elif sys.argv[1] == "show" and sys.argv[2] == "config":
            if (len(sys.argv) == 3):
                load_config()
                USR = [{"User": user.username, "Name": user.realname, "Rights": user.rights} for user in User.query.all()]
                arr = ""
                for usr in USR:
                    arr += f"Login: \"{usr['User']}\" Realname: \"{usr['Name']}\" Rights: \"{usr['Rights']}\"\n\t"
                ACC = [{"Name": ac.name} for ac in Accounts.query.all()]
                arr2 = ""
                for acc in ACC:
                    arr2 += f"Account Name: \"{acc['Name']}\"\n\t"
                print (f"""
    Telegram ChatID:       {TELEGRAM_TOKEN}
    Telegram Token:        {TELEGRAM_CHATID}
    Log file:              {LOG_FILE}
    Encryption Key:        {ENCRYPT_KEY}
    Users:
        {arr}
    CF Accounts:
        {arr2}
                """)
    #else just show help info.
    elif len(sys.argv) <= 2:
        print(f"""Usage: \n{sys.argv[0]} set chat <chatID>
\tAdd Telegram ChatID for notifications.
{sys.argv[0]} set token <Token>
\tAdd Telegram Token for notifications.
{sys.argv[0]} set logpath <new log file path>
\tAdd Telegram Token for notifications.
{sys.argv[0]} user add <login> <password> <realname>
\tAdd new user with its password and default permissions for all cache pathes.
{sys.argv[0]} user setpwd <user> <new password>
\tSet new password for existing user.
{sys.argv[0]} user del <user>
\tDelete existing user by its login
{sys.argv[0]} account add <name> <token>
\tAdd new CF account and its token
{sys.argv[0]} account import <path to file>
\tImport CF account records from file. Format inside the file:
\t<Account name> <token>
{sys.argv[0]} account del <name>
\tDelete CF account entry\n
Info: full script should be launched via UWSGI server. In CLI mode use can only use commands above.
""")
    quit(0)
