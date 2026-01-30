from flask import render_template,Blueprint
import logging,requests,base64
from cryptography.fernet import Fernet
from flask_login import login_required,current_user
from functions.variables import *
from db.database import Accounts
from functions.cache import page_cache

root_bp = Blueprint("root", __name__)
@root_bp.route("/data", methods=['GET'])
@login_required
@page_cache.cached(timeout=300,key_prefix=lambda: f"user:{current_user.realname}")
def return_mainTable():
  try:
    #header for JS filter
    table = '<!-- TABLE_START -->'
    id = 1
    nameserver1 = ""
    nameserver2 = ""
    #getting all permissions from current user as the list
    permissions_list = [item.strip() for item in current_user.rights.split(',')]
    CF_ACCOUNTS = [ {"Name": acc.name, "Token": acc.token} for acc in Accounts.query.all()]
    accounts_menu = "\n<!-- MENU_START -->\n<option value="">👤 Всі аккаунти</option>"
    for account in CF_ACCOUNTS:
      if account['Name'] in permissions_list or "*" in permissions_list:
        headers = {
          'Authorization': f"Bearer {account['Token']}",
          'Content-Type':  'application/json'
        }
        key = base64.urlsafe_b64encode(ENCRYPT_KEY.encode().ljust(32, b'\0'))
        cipher = Fernet(key)
        url = 'https://api.cloudflare.com/client/v4/zones'
        hash = cipher.encrypt(account['Token'].encode('utf-8')).decode('utf-8')
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
          #add current account as the item to filter menu
          cur_account = (response.json()["result"][0]["account"]["name"]).rstrip("\'s Account")
          accounts_menu += f'\n<option value="{cur_account}">{cur_account}</option>'
          for i in response.json()["result"]:
            if not 'name_servers' in i:
              nameserver1 = "None"
              nameserver2 = "None"
            else:
              nameserver1 = i['name_servers'][0]
              nameserver2 = i['name_servers'][1]
            if i['status'] != "active":
              table_status = "table-danger"
            else:
              table_status = "table-success"
            table += f"""
    <tr data-owner="{cur_account}">
      <th scope="row" class="{table_status}">{id}</th>
      <td class="{table_status}"><form method="post" action="/purge"><button type="submit" value="{i['name']}" name="purge" onclick="showLoading()" class="btn btn-primary">Очистити</button>
      <input type="hidden" name="zoneid" value="{i['id']}">
      <input type="hidden" name="hash" value="{hash}"></form></td>
      <td class="{table_status}">{i['name']}</td>
      <td class="{table_status}">{i['status']}</td>
      <td class="{table_status}">{nameserver1}, {nameserver2}</td>
      <td class="{table_status}">{cur_account}</td>
      <td class="{table_status}">{i['id']}</td>
      <td class="{table_status}">{i['original_registrar']}</td>
      <td class="{table_status}">{i['plan']['name']}</td>
    </tr>
    """
            id += 1
        else:
          print(f"Error:{response}")
          logging.error(f"Error:{response}")
    accounts_menu += '\n<!-- MENU_END -->'
    table += '<!-- TABLE_END -->'
    return table + accounts_menu
  except Exception as msg:
    logging.error(f"Error in index(): {msg}")

@root_bp.route("/", methods=['GET'])
@login_required
def return_rootPage():
  try:
    accounts_count = len(Accounts.query.all())
    return render_template("template-main.html",accounts_count=accounts_count)
  except Exception as msg:
    logging.error(f"Error in index(): {msg}")
