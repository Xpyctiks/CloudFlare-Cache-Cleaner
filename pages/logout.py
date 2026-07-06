from flask import redirect,flash,Blueprint,session,request,current_app
from flask_login import current_user
import logging,asyncio
from flask_login import logout_user, login_required, current_user
from functions.send_to_telegram import send_to_telegram

logout_bp = Blueprint("logout", __name__)
@logout_bp.route("/logout/", methods=['POST'])
@login_required
def do_logout():
  """POST request processor: logs the user out"""
  try:
    ip = request.remote_addr
    real_ip = request.headers.get('X-Real-IP', '-.-.-.-')
    logging.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>User {current_user.realname} IP:{ip}, Real-IP:{real_ip} is logging out...")
    logout_user()
    session.clear()
    authelia_logout_url = current_app.config.get("AUTHELIA_LOGOUT_URL", "")
    if authelia_logout_url:
      return redirect(authelia_logout_url, 302)
    flash("Ви успішно вийшли із системи!", "alert alert-info")
    return redirect("/login/",302)
  except Exception as err:
    logging.error(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>do_login(): general error: {err}")
    asyncio.run(send_to_telegram(f"do_login(): general error: {err}",f"🚒Cloud-cache-clean login error:"))
    flash(f"Неочікувана помилка при POST запиту на сторінці /login! Дивіться логи!", 'alert alert-danger')
    return redirect("/login/",302)

@logout_bp.route("/logout/", methods=['GET'])
@login_required
def show_logout():
  """GET request: nothing shoud be here. Returns redirect"""
  try:
    ip = request.remote_addr
    real_ip = request.headers.get('X-Real-IP', '-.-.-.-')
    logging.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>Strange GET request to /logout page: user {current_user.realname} IP:{ip}, Real-IP:{real_ip}")
    flash("Ви не повинні потряпляти на сторінку /logout та ще з GET запитом!", "alert alert-warning")
    return redirect("/",302)
  except Exception as err:
    logging.error(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>show_logout(): general error: {err}")
    asyncio.run(send_to_telegram(f"show_logout(): general error: {err}",f"🚒Cloud-cache-clean logout error:"))
    flash(f"Неочікувана помилка при GET запиту на сторінці /logout! Дивіться логи!", 'alert alert-danger')
    return redirect("/",302)
