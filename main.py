#!/usr/local/bin/python3

from flask import Flask
import sys
from datetime import timedelta
from flask_login import LoginManager
from functions.variables import *
from functions.load_config import load_config
from functions.cli_functions import *
from functions.cache import page_cache

VERSION = "1.1.2"
application = Flask(__name__)
application.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DB_FILE
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
application.config['PERMANENT_SESSION_LIFETIME'] = 28800
application.config['SESSION_COOKIE_SECURE'] = False
application.config['SESSION_COOKIE_HTTPONLY'] = True
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
application.config['SESSION_USE_SIGNER'] = True
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
application.config['CACHE_TYPE'] = 'SimpleCache'
from db.db import db
from db.database import User,Accounts
db.init_app(application)
application.config['SESSION_SQLALCHEMY'] = db
load_config(application)
#key to enсrypt API token in <hidden> filed to easy process of purge method
application.secret_key = application.config["ENCRYPT_KEY"]
login_manager = LoginManager()
login_manager.login_view = "main.login.do_login"
login_manager.session_protection = "strong"
login_manager.init_app(application)
from functions.authelia_auth import try_authelia_login
application.before_request(try_authelia_login)
with application.app_context():
  db.create_all()

@login_manager.user_loader
def load_user(user_id):
  return db.session.get(User,int(user_id))
from pages import blueprint as routes_blueprint
application.register_blueprint(routes_blueprint)
page_cache.init_app(application)

if __name__ == "__main__":
  application.app_context().push()
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
    elif sys.argv[1] == "set" and sys.argv[2] == "authelia":
      if (len(sys.argv) == 4):
        set_autheliaLogoutUrl(sys.argv[3].strip())
      else:
        print("Error! Enter Authelia logout URL")
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
        USR = [{"User": user.username, "Name": user.realname, "Rights": user.rights} for user in User.query.all()]
        arr = ""
        for usr in USR:
          arr += f"Login: \"{usr['User']}\" Realname: \"{usr['Name']}\" Rights: \"{usr['Rights']}\"\n\t"
        ACC = [{"Name": ac.name} for ac in Accounts.query.all()]
        arr2 = ""
        for acc in ACC:
          arr2 += f"Account Name: \"{acc['Name']}\"\n\t"
        print (f"""
  Telegram ChatID: {application.config["TELEGRAM_TOKEN"]}
  Telegram Token:  {application.config["TELEGRAM_CHATID"]}
  Log file:        {application.config["LOG_FILE"]}
  Encryption Key:  {application.config["ENCRYPT_KEY"]}
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
{sys.argv[0]} set authelia <logout URL>
\tSet Authelia logout URL - used to redirect the user to Authelia's own logout endpoint on sign out.
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
