from flask import redirect, flash
from flask_login import login_required, current_user
from functools import wraps
import logging

def rights_required():
  def decorator(func):
    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):
      rights = getattr(current_user, 'rights', '') or ''
      permissions = [item.strip().upper() for item in rights.split(',') if item.strip()]
      if 'ADMIN' not in permissions and '255' not in permissions:
        logging.warning(f"rights_required(): Privilege denied for user {current_user.realname}")
        flash('У вас немає прав доступу до цієї сторінки!', 'alert alert-danger')
        return redirect('/', 302)
      return func(*args, **kwargs)
    return wrapper
  return decorator
