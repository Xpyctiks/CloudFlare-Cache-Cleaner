from .db import db
from werkzeug.security import check_password_hash
from flask_login import UserMixin
from datetime import datetime

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
  autheliaLogoutUrl = db.Column(db.String(512), nullable=True, default="")

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(80), unique=True, nullable=False)
  realname = db.Column(db.String(80), nullable=False)
  password_hash = db.Column(db.String(120), nullable=False)
  rights = db.Column(db.String(), nullable=False, default="*")
  created = db.Column(db.DateTime,default=datetime.now)
  def check_password(self, password):
    return check_password_hash(self.password_hash, password)
