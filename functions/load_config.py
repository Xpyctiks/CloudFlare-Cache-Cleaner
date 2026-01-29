import os, logging,string,random
from db.db import db
from functions.variables import *
from db.database import Settings

def load_config(application) -> None:
  """Important function - loads all configuration values from Sqlite3 database when an application starts"""
  generate_default_config(application)
  with application.app_context():
    try:
      config = db.session.get(Settings, 1)
      application.config.update({
        "TELEGRAM_TOKEN": f"{config.telegramToken}",
        "TELEGRAM_CHATID": f"{config.telegramChat}",
        "LOG_FILE": f"{config.logFile}",
        "ENCRYPT_KEY": f"{config.encryptKey}"
      })
      logging.basicConfig(filename=application.config["LOG_FILE"],level=logging.DEBUG,format='%(asctime)s - Cloudflare-Cache-Cleaner - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
      logging.getLogger('werkzeug').setLevel(logging.WARNING)
    except Exception as msg:
      print(f"Load-config error: {msg}")
      quit(1)

def generate_default_config(application) -> None:
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
