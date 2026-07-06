import logging
from werkzeug.security import generate_password_hash
from functions.variables import *
from db.database import Settings,Accounts,User
from db.db import db

def set_telegramChat(tgChat: str) -> None:
  """CLI only function: sets Telegram ChatID value in database"""
  t = Settings(id=1,telegramChat=tgChat.strip())
  db.session.merge(t)
  db.session.commit()
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
  updated = db.session.get(Settings, 1)
  print(f"logPath updated successfully. New log path: \"{updated.logFile}\"")
  try:
    logging.info(f"logPath updated to \"{updated.logFile}\"")
  except Exception as err:
    pass

def set_autheliaLogoutUrl(url: str) -> None:
  """CLI only function: sets Authelia logout URL value in database"""
  t = Settings(id=1,autheliaLogoutUrl=url)
  db.session.merge(t)
  db.session.commit()
  updated = db.session.get(Settings, 1)
  print(f"Authelia logout URL updated successfully. New value: \"{updated.autheliaLogoutUrl}\"")
  try:
    logging.info(f"Authelia logout URL updated to \"{updated.autheliaLogoutUrl}\"")
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
    print(f"Bulk accounts loaded from file successfully.")
    logging.info(f"Bulk accounts loaded successfully from {file}.")
  except Exception as err:
    logging.error(f"Bulk accounts loading error: {err}")
    print(f"Bulk accounts loading error: {err}")
