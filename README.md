# CloudFlare cache purge 

Python web script to make it easier to purge CloudFlare cache for many accounts and domains.  

-Integrated user management system  
-Logging to Telegram and file  
-Account permissions - you can edit what zones will be available for every user  

# Requirements

-Any uwSGI server.  
-Python packages: bcrypt, flask, cryptography, requests, httpx

# UWSGI server config example:  
```
[uwsgi]
module = cloud-cache-clean:application
http-socket = 0.0.0.0:8880
workers = 1
threads = 2
http-workers = 4
chdir = /opt/CloudFlare-Cache-Cleaner
py-autoreload = 1
daemonize = /var/log/uwsgi/uwsgi.log
uid = www-data
gid = www-data
pidfile = /var/run/uwsgi.pid
logto = /var/log/uwsgi/uwsgi-error.log
plugins = python311
virtualenv = /usr/local/
logto = /var/log/uwsgi.log
```  
# Nginx Unit config example(nginx-unit-config.json file):
```
{
   "listeners": {
     "127.0.0.1:8880": {
       "pass": "applications/cloud-cache-clean"
     }
   },
  "applications": {
    "cloud-cache-clean": {
      "type": "python 3.11",
      "processes": 4,
      "user": "www-data",
      "group": "www-data",
      "working_directory": "/opt/CloudFlare-Cache-Cleaner",
      "home": "/opt/CloudFlare-Cache-Cleaner",
      "path": "/opt/CloudFlare-Cache-Cleaner",
      "module": "cloud-cache-clean",
      "callable": "application"
    }
  }
}
```
  
and command to push it(bash script file):  
```
#!/bin/env bash  
  
curl -X PUT --data-binary @nginx-unit-config.json --unix-socket /var/run/control.unit.sock http://localhost/config  
```  
# Gunicorn settings  
-Systemd unit (for example: /etc/systemd/system/gunicorn-cloud-cache-clean.service). Change to yours:
```
[Unit]
Description=Gunicorn instance for cloud-cache-clean.py
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/CloudFlare-Cache-Cleaner
Environment="PATH=/usr/local/bin"
ExecStart=/usr/bin/gunicorn -c /opt/CloudFlare-Cache-Cleaner/gunicorn_config.py cloud_cache_clean:application
StandardOutput=append:/var/log/gunicorn/cloud-cache-clean.log
StandardError=append:/var/log/gunicorn/cloud-cache-clean-error.log

[Install]
WantedBy=multi-user.target
```
-Gunicorn file(gunicorn_config.py).Change to yours if anything:  
```
import sys
import os

#change to yours
venv_path = "/usr/local/"
sys.path.insert(0, os.path.join(venv_path, "lib/python3.11/site-packages"))
#change to yours
sys.path.insert(0, "/opt/CloudFlare-Cache-Cleaner")

bind = "127.0.0.1:8880"
workers = 3
timeout = 30
loglevel = "info"
wsgi_app = "cloud_cache_clean:application"

```
  