from flask import Blueprint, render_template, request, redirect, flash
from flask_login import login_required, current_user
import logging
from werkzeug.security import generate_password_hash
from db.database import User
from db.db import db
from functions.rights_required import rights_required
from functions.site_actions import is_admin
from sqlalchemy.exc import IntegrityError

admin_panel_bp = Blueprint("admin_panel", __name__)

@admin_panel_bp.route("/admin_panel/", methods=['GET'])
@login_required
@rights_required()
def admin_panel_index():
  return redirect("/admin_panel/users/", 302)

@admin_panel_bp.route("/admin_panel/users/", methods=['GET', 'POST'])
@login_required
@rights_required()
def admin_panel_users():
  try:
    if request.method == 'POST':
      if 'buttonDeleteUser' in request.form:
        user_id = request.form.get('buttonDeleteUser')
        user = User.query.get(int(user_id)) if user_id and user_id.isdigit() else None
        if user:
          if user.id == current_user.id:
            flash('Ви не можете видалити себе.', 'alert alert-warning')
          else:
            db.session.delete(user)
            db.session.commit()
            flash(f'Користувача {user.username} видалено.', 'alert alert-success')
        else:
            flash('Користувача не знайдено.', 'alert alert-danger')
        return redirect('/admin_panel/users/', 302)
      if 'buttonToggleAdmin' in request.form:
        user_id = request.form.get('buttonToggleAdmin')
        user = User.query.get(int(user_id)) if user_id and user_id.isdigit() else None
        if user:
          rights = [item.strip().upper() for item in (user.rights or '').split(',') if item.strip()]
          if 'ADMIN' in rights or '255' in rights:
            rights = [item for item in rights if item not in ('ADMIN', '255')]
            user.rights = ', '.join(rights)
            flash(f'Права адміністратора з користувача {user.username} знято.', 'alert alert-success')
          else:
            rights.append('ADMIN')
            user.rights = ', '.join(filter(None, rights))
            flash(f'Користувач {user.username} отримав права адміністратора.', 'alert alert-success')
          db.session.commit()
        else:
          flash('Користувача не знайдено.', 'alert alert-danger')
        return redirect('/admin_panel/users/', 302)
      if 'buttonAddUser' in request.form:
        username = request.form.get('new-username', '').strip()
        password = request.form.get('new-password', '').strip()
        realname = request.form.get('new-realname', '').strip()
        rights = request.form.get('new-rights', '').strip()
        if request.form.get('new-is-admin'):
          rights = ', '.join(filter(None, [rights, 'ADMIN']))
        if not username or not password or not realname:
          flash('Логін, пароль та ім’я обов’язкові.', 'alert alert-warning')
          return redirect('/admin_panel/users/', 302)
        if User.query.filter_by(username=username).first():
          flash(f'Користувач {username} вже існує.', 'alert alert-warning')
          return redirect('/admin_panel/users/', 302)
        new_user = User(
            username=username,
            realname=realname,
            password_hash=generate_password_hash(password),
            rights=rights or ''
        )
        db.session.add(new_user)
        try:
          db.session.commit()
          flash(f'Користувача {username} створено.', 'alert alert-success')
        except IntegrityError:
          db.session.rollback()
          flash('Помилка при збереженні користувача.', 'alert alert-danger')
        return redirect('/admin_panel/users/', 302)
    users = User.query.order_by(User.username).all()
    return render_template('template-admin_panel.html', users=users, active_users='active', admin_panel=is_admin())
  except Exception as err:
    logging.error(f'admin_panel_users(): global error {err}')
    flash('Неочікувана помилка адмін-панелі.', 'alert alert-danger')
    return redirect('/', 302)
