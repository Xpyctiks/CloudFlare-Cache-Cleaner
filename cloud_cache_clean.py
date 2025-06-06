#!/usr/local/bin/python3

from flask import Flask,render_template,request,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
import os, httpx, asyncio, sys, logging, random, string,requests
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

CONFIG_DIR = os.path.join("/etc/",os.path.basename(__file__).split(".py")[0])
DB_FILE = os.path.join(CONFIG_DIR,os.path.basename(__file__).split(".py")[0]+".db")
TELEGRAM_TOKEN = TELEGRAM_CHATID = LOG_FILE = ""
CRYPT_KEY = b""
application = Flask(__name__)
application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.config['PERMANENT_SESSION_LIFETIME'] = 28800
db = SQLAlchemy(application)
login_manager = LoginManager(application)
login_manager.login_view = "login"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    realname = db.Column(db.String(80), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    permissions = db.Column(db.Text,default="*")
    created = db.Column(db.DateTime,default=datetime.now)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegramChat = db.Column(db.String(16), nullable=True)
    telegramToken = db.Column(db.String(64), nullable=True)
    logFile = db.Column(db.String(512), nullable=True)
    sessionKey = db.Column(db.String(64), nullable=True)
    cryptKey = db.Column(db.String(64), nullable=True)

class CFAccounts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    accountName = db.Column(db.String(32), nullable=False, unique=True)
    accountToken = db.Column(db.String(512), nullable=False, unique=True)
    created = db.Column(db.DateTime,default=datetime.now)

def generate_default_config():
    if not os.path.isfile(DB_FILE):
        length = 64
        characters = string.ascii_letters + string.digits
        session_key = ''.join(random.choice(characters) for _ in range(length))
        cryptKey = Fernet.generate_key()
        default_settings = Settings(id=1, telegramChat="", telegramToken="", logFile="/var/log/cloud-cache-clean.log", sessionKey=session_key, cryptKey=cryptKey)
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

def set_telegramChat(tgChat):
    t = Settings(id=1,telegramChat=tgChat.strip())
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram ChatID added successfully")
    try:
        logging.info(f"Telegram ChatID updated successfully!")
    except Exception as err:
        pass

def set_telegramToken(tgToken):
    t = Settings(id=1,telegramToken=tgToken)
    db.session.merge(t)
    db.session.commit()
    load_config()
    print("Telegram Token added successfully")
    try:
        logging.info(f"Telegram Token updated successfully!")
    except Exception as err:
        pass

def set_logpath(logpath):
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

def register_user(username,password,realname):
    try:
        if User.query.filter_by(username=username).first():
            print(f"User \"{username}\" creation error - already exists!")
            logging.error(f"User \"{username}\" creation error - already exists!")
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                realname=realname,
                permissions = "*"
            )
            db.session.add(new_user)
            db.session.commit()
            load_config()
            print(f"New user \"{username}\" - \"{realname}\" created successfully!")
            logging.info(f"New user \"{username}\" - \"{realname}\" created successfully!")
    except Exception as err:
        logging.error(f"User \"{username}\" - \"{realname}\" creation error: {err}")
        print(f"User \"{username}\" - \"{realname}\" creation error: {err}")

def update_user(username,password):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            d = User(id=user.id,password_hash=generate_password_hash(password))
            db.session.merge(d)
            db.session.commit()
            load_config()
            print(f"Password for user \"{user.username}\" updated successfully!")
            logging.info(f"Password for user \"{user.username}\" updated successfully!")
        else:
            print(f"User \"{user.username}\" set password error - no such user!")
            logging.error(f"User \"{user.username}\" set password error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{user.username}\" set password error: {err}")
        print(f"User \"{user.username}\" set password error: {err}")

def delete_user(username):
    try:
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            load_config()
            print(f"User \"{user.username}\" deleted successfully!")
            logging.info(f"User \"{user.username}\" deleted successfully!")
        else:
            print(f"User \"{user.username}\" delete error - no such user!")
            logging.error(f"User \"{user.username}\" delete error - no such user!")
            quit(1)
    except Exception as err:
        logging.error(f"User \"{user.username}\" delete error: {err}")
        print(f"User \"{user.username}\" delete error: {err}")

def add_cfaccount(name,token):
    try:
        new_acc = CFAccounts(accountName=name, accountToken=token)
        db.session.add(new_acc)
        db.session.commit()
        updated = CFAccounts.query.filter_by(accountName=name).first()
        print(f"Account \"{updated.accountName}\" - \"{updated.accountToken}\" added successfully.")
        logging.info(f"Account \"{updated.accountName}\" added successfully.")
    except Exception as err:
        logging.error(f"Add account error: {err}")
        print(f"Add account error: {err}")

def del_cfaccount(name):
    try:
        del_acc = CFAccounts.query.filter_by(accountName=name).first()
        if del_acc:
            name = del_acc.accountName
            token = del_acc.accountToken
            db.session.delete(del_acc)
            db.session.commit()
            print(f"Account \"{name}\" deleted successfully.")
            logging.info(f"Account \"{name}\" deleted successfully.")
    except Exception as err:
        logging.error(f"Del account error: {err}")
        print(f"Del account error: {err}")

def import_cfaccounts(file):
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
                new_entry = CFAccounts(accountName=name, accountToken=token)
                db.session.add(new_entry)
        db.session.commit()
        load_config()
        print(f"Bulk account settings loaded from file successfully.")
        logging.info(f"Bulk account settings loaded successfully from {file}.")
    except Exception as err:
        logging.error(f"Bulk account loading error: {err}")
        print(f"Bulk account loading error: {err}")

async def send_to_telegram(subject,message):
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

def load_config():
    #main initialization phase starts here
    global TELEGRAM_TOKEN, TELEGRAM_CHATID, LOG_FILE, CRYPT_KEY
    try:
        config = db.session.get(Settings, 1)
        TELEGRAM_TOKEN = config.telegramToken
        TELEGRAM_CHATID = config.telegramChat
        LOG_FILE = config.logFile
        CRYPT_KEY = config.cryptKey
        application.secret_key = config.sessionKey
        try:
            logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - Cloud-cache-clean - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
        except Exception as msg:
            logging.error(msg)
            print(f"Load-config error: {msg}")
            quit(1)
    except Exception as msg:
        print(f"Load-config error: {msg}")
        quit(1)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User,int(user_id))

#catch logout form. Deleting cookies and redirect to /
@application.route("/logout", methods=['POST'])
@login_required
def logout():
    logout_user()
    flash("You are logged out", "alert alert-info")
    return redirect(url_for("login"),301)

@application.route("/purge", methods=['POST'])
@login_required
def purge():
    if request.form['purge'] and request.form['zoneid'] and request.form['hash']:
        cipher = Fernet(CRYPT_KEY)
        token = cipher.decrypt(request.form['hash'].encode('utf-8')).decode('utf-8')
        #if proper record and its token found:
        try:
            headers = {
                'Authorization': f"Bearer {token}",
                'Content-Type':  'application/json'
            }
            url = f"https://api.cloudflare.com/client/v4/zones/{request.form['zoneid']}/purge_cache"
            response = requests.post(url, json={"purge_everything": True}, headers=headers)
            if response.status_code == 200:
                asyncio.run(send_to_telegram("🍀Cloud-Cache-Clean:",f"Cache for {request.form['purge']} purged successfully by {current_user.username}!"))
                logging.info(f"CloudFlare cache for {request.form['purge']} purged successfully by {current_user.username}!")
                flash(f"Cache for {request.form['purge']} purged successfully.", "alert alert-success")
                return redirect("/",301)
            else:
                asyncio.run(send_to_telegram("💢Cloud-Cache-Clean:",f"Error puring cache for {request.form['purge']} by {current_user.username}!"))
                logging.error(f"Error puring cache for {request.form['purge']} by {current_user.username}!")
                flash(f"Error purging {request.form['purge']} - some error while purge. See logs.", "alert alert-warning")
                return redirect("/",301)
        except Exception as msg:
            logging.error(f"Error: Some errors during purging - {request.form['purge']} - {msg}!")
            asyncio.run(send_to_telegram("💢Cloud-Cache-Clean:",f"Error: Some errors during purge of {request.form['purge']} by {current_user.username} - {msg}"))
            flash(f"Purge error: Zone: {request.form['purge']} by {current_user.username} - some error while purge. See logs.", "alert alert-warning")
            return redirect("/",301)
    #proper record and its token is not found:
    else:
        logging.error(f"Purge error by {current_user.username} - some important values from web form were not sent")
        asyncio.run(send_to_telegram("💢Cloud-Cache-Clean:",f"Purge error by {current_user.username} - some important values from web form were not sent"))
        flash(f"Purge error: {request.form['purge']} - some important values from web form were not sent", "alert alert-warning")
        return redirect("/",301)

#catch login form. Check if user exists in the list and password is correct. If yes - set cookies and redirect to /
@application.route("/login", methods=['GET','POST'])
def login():
    #is this is POST request so we are trying to login
    if request.method == 'POST':
        if current_user.is_authenticated:
            return redirect('/',301)
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            logging.info(f"Login: User {username} logged in")
            return redirect("/",301)
        else:
            logging.error(f"Login: Wrong password \"{password}\" for user \"{username}\"")
            asyncio.run(send_to_telegram("🚷Cloud-Cache-Clean:",f"Login error.Wrong password for user \"{username}\""))
            flash('Wrong username or password!', 'alert alert-danger')
            return render_template("template-login.html")    
    if current_user.is_authenticated:
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
        data = User.query.filter_by(username=current_user.username).first()
        if data:
            permissions_list = [item.strip() for item in data.permissions.split(',')]
        accounts = CFAccounts.query.all()
        for i, s in enumerate(accounts, 1):
            if s.accountName in permissions_list or "*" in permissions_list:
                headers = {
                    'Authorization': f"Bearer {s.accountToken}",
                    'Content-Type':  'application/json'
                }
                url = 'https://api.cloudflare.com/client/v4/zones'
                response = requests.get(url, headers=headers)
                cipher = Fernet(CRYPT_KEY)
                hash = cipher.encrypt(s.accountToken.encode('utf-8')).decode('utf-8')
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
                            <td class="table-danger"></td>
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
                    print(f"Response error:{response}")
                    logging.error(f"Response error:{response}")
        return render_template("template-main.html",table=table)
    except Exception as msg:
        logging.error(f"Error in index(/): {msg}")

if __name__ == "__main__":
    application.app_context().push()
    generate_default_config()
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
        elif sys.argv[1] == "cfaccount" and sys.argv[2] == "add":
            if (len(sys.argv) == 5):
                add_cfaccount(sys.argv[3].strip(),sys.argv[4].strip())
            else:
                print("Error! Enter both Name and CF account token")
        elif sys.argv[1] == "cfaccount" and sys.argv[2] == "import":
            if (len(sys.argv) == 4):
                import_cfaccounts(sys.argv[3].strip())
            else:
                print("Error! Enter path to file with CF accounts list")
        elif sys.argv[1] == "cfaccount" and sys.argv[2] == "del":
            if (len(sys.argv) == 4):
                del_cfaccount(sys.argv[3].strip())
            else:
                print("Error! Enter name of CF account entry to delete")
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
{sys.argv[0]} cfaccount add <name> <token>
\tAdd new CF account and its token
{sys.argv[0]} cfaccount import <path to file>
\tImport CF account records from file
{sys.argv[0]} cfaccount del <name>
\tDelete CF account entry\n
Info: full script should be launched via UWSGI server. In CLI mode use can only use commands above.
""")
    quit(0)
else:
    application.app_context().push()
    generate_default_config()
    load_config()
