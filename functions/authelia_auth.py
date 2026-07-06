import logging
from flask import request, flash, render_template
from flask_login import current_user, login_user
from datetime import timedelta
from db.database import User

REMOTE_USER_HEADER = "Remote-User"

def try_authelia_login():
  """If Authelia's Remote-User header is present, auto-login the matching local user (hybrid mode)."""
  if request.endpoint == "static" or current_user.is_authenticated:
    return
  remote_user = request.headers.get(REMOTE_USER_HEADER)
  if not remote_user:
    return
  user = User.query.filter_by(username=remote_user).first()
  if not user:
    logging.warning(f"try_authelia_login(): Authelia identified '{remote_user}' but no matching local account exists - denying access")
    flash('Ваш обліковий запис підтверджено через Authelia, але він не зареєстрований у цій системі. Зверніться до адміністратора.', 'alert alert-danger')
    return render_template("template-login.html"), 403
  login_user(user, remember=True, duration=timedelta(hours=8))
  logging.info(f"try_authelia_login(): User {user.realname} auto-logged in via Authelia header")
