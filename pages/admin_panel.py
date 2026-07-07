import re
from flask import Blueprint, render_template, request, redirect, flash, current_app, jsonify
from flask_login import login_required, current_user
import logging
from werkzeug.security import generate_password_hash
from db.database import User, Settings, Accounts
from db.db import db
from functions.rights_required import rights_required
from functions.site_actions import is_admin
from sqlalchemy.exc import IntegrityError

admin_panel_bp = Blueprint("admin_panel", __name__)

def natural_sort_key(text):
  return [int(chunk) if chunk.isdigit() else chunk.lower() for chunk in re.split(r'(\d+)', text or '')]

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
    return render_template('template-admin_panel.html', page='users', users=users, admin_panel=is_admin())
  except Exception as err:
    logging.error(f'admin_panel_users(): global error {err}')
    flash('Неочікувана помилка адмін-панелі.', 'alert alert-danger')
    return redirect('/', 302)

@admin_panel_bp.route("/admin_panel/settings/", methods=['GET', 'POST'])
@login_required
@rights_required()
def admin_panel_settings():
  try:
    if request.method == 'POST':
      if 'buttonSaveSettings' in request.form:
        telegram_chat = request.form.get('telegramChat', '').strip()
        telegram_token = request.form.get('telegramToken', '').strip()
        log_file = request.form.get('logFile', '').strip()
        encrypt_key = request.form.get('encryptKey', '').strip()
        authelia_logout_url = request.form.get('autheliaLogoutUrl', '').strip()
        if not log_file or not encrypt_key:
          flash('Шлях до лог-файлу та ключ шифрування обов’язкові.', 'alert alert-warning')
          return redirect('/admin_panel/settings/', 302)
        settings = db.session.get(Settings, 1)
        settings.telegramChat = telegram_chat
        settings.telegramToken = telegram_token
        settings.logFile = log_file
        settings.encryptKey = encrypt_key
        settings.autheliaLogoutUrl = authelia_logout_url
        db.session.commit()
        current_app.config.update({
          "TELEGRAM_TOKEN": telegram_token,
          "TELEGRAM_CHATID": telegram_chat,
          "LOG_FILE": log_file,
          "ENCRYPT_KEY": encrypt_key,
          "AUTHELIA_LOGOUT_URL": authelia_logout_url
        })
        flash('Налаштування збережено. Зміна шляху до лог-файлу застосується повністю лише після перезапуску застосунку.', 'alert alert-success')
      return redirect('/admin_panel/settings/', 302)
    settings = db.session.get(Settings, 1)
    return render_template('template-admin_panel.html', page='settings', settings=settings, admin_panel=is_admin())
  except Exception as err:
    logging.error(f'admin_panel_settings(): global error {err}')
    flash('Неочікувана помилка адмін-панелі.', 'alert alert-danger')
    return redirect('/', 302)

@admin_panel_bp.route("/admin_panel/accounts/", methods=['GET', 'POST'])
@login_required
@rights_required()
def admin_panel_accounts():
  try:
    if request.method == 'POST':
      if 'buttonDeleteAccount' in request.form:
        account_id = request.form.get('buttonDeleteAccount')
        account = Accounts.query.get(int(account_id)) if account_id and account_id.isdigit() else None
        if account:
          db.session.delete(account)
          db.session.commit()
          flash(f'Аккаунт {account.name} видалено.', 'alert alert-success')
        else:
          flash('Аккаунт не знайдено.', 'alert alert-danger')
        return redirect('/admin_panel/accounts/', 302)
      if 'buttonAddAccount' in request.form:
        name = request.form.get('new-account-name', '').strip()
        token = request.form.get('new-account-token', '').strip()
        if not name or not token:
          flash('Назва аккаунта та токен обов’язкові.', 'alert alert-warning')
          return redirect('/admin_panel/accounts/', 302)
        if Accounts.query.filter_by(name=name).first():
          flash(f'Аккаунт {name} вже існує.', 'alert alert-warning')
          return redirect('/admin_panel/accounts/', 302)
        if Accounts.query.filter_by(token=token).first():
          flash('Аккаунт з таким токеном вже існує.', 'alert alert-warning')
          return redirect('/admin_panel/accounts/', 302)
        new_account = Accounts(name=name, token=token)
        db.session.add(new_account)
        try:
          db.session.commit()
          flash(f'Аккаунт {name} створено.', 'alert alert-success')
        except IntegrityError:
          db.session.rollback()
          flash('Помилка при збереженні аккаунта.', 'alert alert-danger')
        return redirect('/admin_panel/accounts/', 302)
    accounts = sorted(Accounts.query.all(), key=lambda acc: natural_sort_key(acc.name))
    return render_template('template-admin_panel.html', page='accounts', accounts=accounts, admin_panel=is_admin())
  except Exception as err:
    logging.error(f'admin_panel_accounts(): global error {err}')
    flash('Неочікувана помилка адмін-панелі.', 'alert alert-danger')
    return redirect('/', 302)

@admin_panel_bp.route("/admin_panel/accounts/rename", methods=['POST'])
@login_required
@rights_required()
def admin_panel_accounts_rename():
  try:
    data = request.get_json(silent=True) or {}
    account_id = data.get('id')
    new_name = (data.get('name') or '').strip()
    account = Accounts.query.get(int(account_id)) if str(account_id or '').isdigit() else None
    if not account:
      return jsonify(success=False, message='Аккаунт не знайдено.'), 404
    if not new_name:
      return jsonify(success=False, message='Назва не може бути порожньою.'), 400
    if new_name != account.name and Accounts.query.filter_by(name=new_name).first():
      return jsonify(success=False, message=f'Аккаунт {new_name} вже існує.'), 400
    account.name = new_name
    db.session.commit()
    return jsonify(success=True, name=account.name)
  except Exception as err:
    logging.error(f'admin_panel_accounts_rename(): global error {err}')
    db.session.rollback()
    return jsonify(success=False, message='Неочікувана помилка.'), 500
