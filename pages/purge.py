from flask import redirect,Blueprint,request,flash,make_response
from flask_login import login_required, current_user
import logging,asyncio,base64,requests
from db.database import *
from functions.variables import *
from cryptography.fernet import Fernet
from functions.send_to_telegram import send_to_telegram

purge_bp = Blueprint("purge", __name__)
@purge_bp.route("/purge/", methods=['POST'])
@login_required
def purge():
  if request.method == 'POST':
    key = base64.urlsafe_b64encode(ENCRYPT_KEY.encode().ljust(32, b'\0'))
    cipher = Fernet(key)
    token = cipher.decrypt(request.form.get('hash').encode('utf-8')).decode('utf-8')
    headers = {
      'Authorization': f"Bearer {token}",
      'Content-Type':  'application/json'
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{request.form['zoneid']}/purge_cache"
    response = requests.post(url, json={"purge_everything": True}, headers=headers)
    if response.status_code == 200:
      asyncio.run(send_to_telegram(f"🍀CloudFlare cache of {request.form.get('purge')} purged successfully by {current_user.realname}!"))
      logging.info(f"CloudFlare cache of {request.form.get('purge')} purged successfully by {current_user.realname}!")
      response = make_response(redirect("/"),301)
      flash(f"Cache of {request.form.get('purge')} purged successfully!", "alert alert-success")
      return response
    else:
      asyncio.run(send_to_telegram(f"💢Error purging CloudFlare cache for {request.form.get('purge')} by {current_user.realname}!"))
      logging.error(f"Error purging CloudFlare cache for {request.form.get('purge')} by {current_user.realname}!")
      response = make_response(redirect("/"),301)
      flash(f"{request.form.get('zoneid')} purge error!", "alert alert-danger")
      return response
  else:
    response = make_response(redirect("/"),301)
    return response
