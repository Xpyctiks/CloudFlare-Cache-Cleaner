# CloudFlare cache purge 

Python web script to make it easier to purge CloudFlare cache for many accounts and domains.  

-Integrated user management system  
-Logging to Telegram and file  
-Account permissions - you can edit what zones will be available for every user  

# Requirements

-Any uwSGI server.  
-Python packages: bcrypt, flask, cryptography, requests, httpx

-UWSGI server config example:  
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
-Nginx Unit config example(nginx-unit-config.json file):
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