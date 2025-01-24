#!/usr/bin/env python3

from flask import Flask,render_template,request,make_response,redirect
import os
import sys
import json
import logging
import logging.handlers
import requests
import bcrypt
from cryptography.fernet import Fernet

CONFIG_FILE = os.path.abspath(os.path.dirname(__file__))+"/cloud-cache-clean.conf"
PASSWORD_FILE = os.path.abspath(os.path.dirname(__file__))+"/user-pass.conf"
#salt for encrypt cookie
COOKIE_SALT = ""
#key to ecnrypt API token in <hidden> filed to easy process of purge method
CRYPT_KEY = b""
PWD_LIST = []
TELEGRAM_TOKEN = ""
TELEGRAM_CHATID = ""
LOG_FILE = ""
CF_ACCOUNTS = []
application = Flask(__name__)

def load_config():
    error = 0
    #Check if config file exists. If not - generate the new one.
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r',encoding='utf8') as file:
            config = json.load(file)
        #Check if all parameters are set. If not - shows the error message
        for id,key in enumerate(config.keys()):
            if not config.get(key):
                print(f"Parameter {key} is not defined!")
                error+=1
        if error != 0:
            print(f"Some variables are not set in config file. Please fix it then run the program again.")
            quit()
        global TELEGRAM_TOKEN
        global TELEGRAM_CHATID
        global LOG_FILE
        global CF_ACCOUNTS
        global COOKIE_SALT
        global CRYPT_KEY
        TELEGRAM_TOKEN = config.get('telegramToken')
        TELEGRAM_CHATID = config.get('telegramChat')
        LOG_FILE = config.get('logFile')
        COOKIE_SALT = config.get('cookie_salt')
        CRYPT_KEY = config.get('crypt_key')
        CF_ACCOUNTS = config.get('CFaccounts', [])
        logging.basicConfig(filename=LOG_FILE,level=logging.INFO,format='%(asctime)s - Cloud-cache-clean - %(levelname)s - %(message)s',datefmt='%d-%m-%Y %H:%M:%S')
    else:
        generate_default_config()
    #Check if user/password file exists. If not - generate the new one.
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, 'r',encoding='utf8') as file:
            global PWD_LIST
            PWD_LIST = json.load(file)
    else:
        generate_default_config2()

def generate_default_config():
    config1 = {
        "telegramToken": "",
        "telegramChat": "",
        "logFile": "/var/log/cloud-cache-clean.log",
        "CFaccounts": [
        {
            "Token": "111111111",
            "Name": "Account1"
        },
        {
            "Token": "222222222",
            "Name": "Account2"
        }
        ]
    }
    with open(CONFIG_FILE, 'w',encoding='utf8') as file:
        json.dump(config1, file, indent=4)
    os.chmod(CONFIG_FILE, 0o600)
    print(f"First launch. New config file {CONFIG_FILE} generated and needs to be configured.")
    quit()

def generate_default_config2():
    config2 = {
        "admin": {
            "Password": "",
            "Name": "Administrator",
            "Permissions": "*"
        },
        "user": {
            "Password": "",
            "Name": "User",
            "Permissions": "Account1,Account2"
        }
    }
    with open(PASSWORD_FILE, 'w',encoding='utf8') as file:
        json.dump(config2, file, indent=4)
    os.chmod(PASSWORD_FILE, 0o600)
    print(f"First launch. New user/password file {PASSWORD_FILE} generated and needs to be configured.")
    quit()

def send_to_telegram(subject,message):
    headers = {
        'Content-Type': 'application/json',
    }
    data = {
        "chat_id": f"{TELEGRAM_CHATID}",
        "text": f"{subject}\n{message}",
    }
    response = requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",headers=headers,json=data)
    if response.status_code != 200:
        err = response.json()
        logging.error(f"Error while sending message to Telegram: {err}")

#catch logout form. Deleting cookies and redirect to /
@application.route("/logout", methods=['POST'])
def logout():
    logging.info(f"Logout: User {request.cookies.get('username')} logged out")
    response = make_response(redirect("/"),301)
    response.delete_cookie("realname")
    response.delete_cookie("username")
    response.delete_cookie("SESSID")
    return response

@application.route("/purge", methods=['POST'])
def purge():
    if request.method == 'POST':
        cipher = Fernet(CRYPT_KEY)
        token = cipher.decrypt(request.form['hash'].encode('utf-8')).decode('utf-8')
        headers = {
            'Authorization': f"Bearer {token}",
            'Content-Type':  'application/json'
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{request.form['zoneid']}/purge_cache"
        response = requests.post(url, json={"purge_everything": True}, headers=headers)
        if response.status_code == 200:
            send_to_telegram("🍀Cloud-Cache-Clean:",f"CloudFlare cache for {request.form['purge']} purged successfully by {request.cookies.get('realname')}!")
            logging.info(f"CloudFlare cache for {request.form['purge']} purged successfully by {request.cookies.get('realname')}!")
            response = make_response(redirect("/"),301)
            response.set_cookie("result", f"Purged successfully!", max_age=5)
            return response
        else:
            send_to_telegram("💢Cloud-Cache-Clean:",f"Error puring CloudFlare cache for {request.form['purge']} by {request.cookies.get('realname')}!")
            logging.error(f"Error puring CloudFlare cache for {request.form['purge']} by {request.cookies.get('realname')}!")
            response = make_response(redirect("/"),301)
            response.set_cookie("result", f"Some error during purge operation!", max_age=5)
            return response
    else:
        response = make_response(redirect("/"),301)
        return response

#catch login form. Check if user exists in the list and password is correct. If yes - set cookies and redirect to /
@application.route("/login", methods=['GET','POST'])
def login():
    #is this is POST request so we are trying to login
    if request.method == 'POST':
        check = 0
        #searching for the given user in the list.break when found
        for id,user in enumerate(PWD_LIST.keys()):
            if request.form['username'] == user:
                check = 1
                break
        if check == 1:
            if bcrypt.checkpw(request.form['password'].encode('utf-8'), PWD_LIST[user]['Password'].encode('utf-8')):
                response = make_response(redirect("/"),301)
                response.set_cookie("realname", PWD_LIST[user]['Realname'], max_age=60*60*8)
                response.set_cookie("username", user, max_age=60*60*8)
                #creating encrypted cookie data
                data = f"{COOKIE_SALT}{request.form['username']}".encode('utf-8')
                response.set_cookie(f"SESSID", bcrypt.hashpw(data,bcrypt.gensalt()).decode('utf-8'), max_age=60*60*8)
                logging.info(f"Login: User {request.form['username']} logged in")
                return response
            else:
                #if password is incorrect - show error message.Adding error message to the login form
                loginError = f"""<div class=\"alert alert-danger alert-dismissible fade show\" role=\"alert\" style=\"margin-top: 15px;\">
                Wrong username or password!"
                <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" aria-label=\"Close\"></button>
                </div>"""
                logging.error(f"Login: Wrong password \"{request.form['password']}\" for user \"{request.form['username']}\"")
                send_to_telegram("🚷Cloud-Cache-Clean:",f"Login error.Wrong password for user \"{request.form['username']}\"")
                return render_template("template-login.html",loginError=loginError)
        #if user is not found - show error message.Adding error message to the login form
        else:
            loginError = f"""<div class=\"alert alert-danger alert-dismissible fade show\" role=\"alert\" style=\"margin-top: 15px;\">
            Wrong username or password!
            <button type=\"button\" class=\"btn-close\" data-bs-dismiss=\"alert\" aria-label=\"Close\"></button>
            </div>"""
            logging.error(f"Login: Unknown user \"{request.form['username']}\", password \"{request.form['password']}\"")
            send_to_telegram("🚷Cloud-Cache-Clean:",f"Login error: Unknown user \"{request.form['username']}\" login attempt!")
            return render_template("template-login.html",loginError=loginError)
    #if this is GET request - just show login form
    if request.method == 'GET':
        return render_template("template-login.html")
    
@application.route("/", methods=['GET'])
def index():
    load_config()
    if request.cookies.get("SESSID") and request.cookies.get("realname") and request.cookies.get("username"):
        #searching for the given user in the list
        for id,user in enumerate(PWD_LIST.keys()):
            dataLocal = f"{COOKIE_SALT}{request.cookies.get('username')}".encode('utf-8')
            dataReceived = request.cookies.get('SESSID').encode('utf-8')
            #checking if user is found and encrypted cookie he sent is correct
            if bcrypt.checkpw(dataLocal,dataReceived):
                res = request.cookies.get("result")
                if res == None:
                    return index2(request.cookies.get("realname"),"")
                else:
                    result = f"alert('{res}')"
                    return index2(request.cookies.get("realname"),result=result)
            else:
                return render_template("template-login.html")
    else:
        response = make_response(redirect("/login"),301)
        return response

def index2(realname,result):
    try:
        table = ""
        id = 1
        nameserver1 = ""
        nameserver2 = ""
        #getting all permissions from current user as the list
        permissions_list = [item.strip() for item in PWD_LIST[request.cookies.get("username")]['Permissions'].split(',')]
        for account in CF_ACCOUNTS:
            if account['Name'] in permissions_list or "*" in permissions_list:
                headers = {
                    'Authorization': f"Bearer {account['Token']}",
                    'Content-Type':  'application/json'
                }
                cipher = Fernet(CRYPT_KEY)
                url = 'https://api.cloudflare.com/client/v4/zones'
                hash = cipher.encrypt(account['Token'].encode('utf-8')).decode('utf-8')
                response = requests.get(url, headers=headers) 
                if response.status_code == 200:
                    for i in response.json()["result"]:
                        if not 'name_servers' in i:
                            nameserver1 = "None"
                            nameserver2 = "None"
                        else:
                            nameserver1 = i['name_servers'][0]
                            nameserver2 = i['name_servers'][1]
                        if i['status'] != "active":
                            table += f"""\n<tr>\n<th scope="row" class="table-danger">{id}</th>
                            <td class="table-danger"><form method="post" action="/purge"><button type="submit" value="{i['name']}" name="purge" class="btn btn-primary">Purge Cache</button>
                            <input type="hidden" name="zoneid" value="{i['id']}">
                            <input type="hidden" name="hash" value="{hash}"></form></td>
                            <td class="table-danger">{i['name']}</td>
                            <td class="table-danger">{i['status']}</td>
                            <td class="table-danger">{nameserver1}, {nameserver2}</td>
                            <td class="table-danger">{i['account']['name']}</td>
                            <td class="table-danger">{i['id']}</td>
                            <td class="table-danger">{i['original_registrar']}</td>
                            <td class="table-danger">{i['plan']['name']}</td>\n</tr>"""
                        else:
                            table += f"""\n<tr>\n<th scope="row" class="table-success">{id}</th>
                            <td class="table-success"><form method="post" action="/purge"><button type="submit" value="{i['name']}" name="purge" class="btn btn-primary">Purge Cache</button>
                            <input type="hidden" name="zoneid" value="{i['id']}">
                            <input type="hidden" name="hash" value="{hash}"></form></td>
                            <td class="table-success">{i['name']}</td>
                            <td class="table-success">{i['status']}</td>
                            <td class="table-success">{nameserver1}, {nameserver2}</td>
                            <td class="table-success">{i['account']['name']}</td>
                            <td class="table-success">{i['id']}</td>
                            <td class="table-success">{i['original_registrar']}</td>
                            <td class="table-success">{i['plan']['name']}</td>\n</tr>"""
                        id += 1
                else:
                    print(f"Error:{response}")
                    logging.error(f"Error:{response}")
        if result == "":
            return render_template("template-main.html",table=table,realName=realname)
        else:
            return render_template("template-main.html",table=table,realName=realname,result=result)
    except Exception as msg:
        logging.error(f"Error in index2(): {msg}")

def genpwd():
    if len(sys.argv) < 3:
        print(f"Password not provided. Usage: {sys.argv[0]} genpwd <password>")
        quit()
    password = sys.argv[2]
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    print(f"Password: {password}\nHash: {hashed}")
    quit()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h" or sys.argv[1] == "help":
            print(f"""Usage: {sys.argv[0]} genpwd <password>
            You will get the hash of the password. Add block to the user-pass.conf file in JSON format:
            {{
                "<username>": {{
                    "realname": "<Real Name>",
                    "password": "<hash you've generated>"
                }}
            }}""")
            quit()
        #if we are generating the password hash
        elif sys.argv[1] == "genpwd":
            genpwd()
        else:
            print(f"Something went wrong. Please check the parameters.")
            quit()
    load_config()
