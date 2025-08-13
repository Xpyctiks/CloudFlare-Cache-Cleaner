-Python web application with CLI functions allows to purge CloudFlare sites cache from many accounts at the same page.  
-Uses sqlite3 DB to store options.  
-User management and CF accounts management via CLI.  
-Bulk import of CF accounts from a file in simple format:  
<<AccountName>> <<Token>>  
-Sending important alerts and notification to Telegram if ChatID and Token are set.  

# Gunicorn settings  
-Systemd unit (for example: /etc/systemd/system/gunicorn-cloudflare-cache-cleaner.service). Change to yours:
```
[Unit]
Description=Gunicorn instance for Cloudflare-cache-cleaner.py
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/Cloudflare-cache-cleaner
Environment="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/usr/bin/gunicorn -c /opt/Cloudflare-cache-cleaner/gunicorn_config.py Cloudflare_cache_cleaner:application
StandardOutput=append:/var/log/gunicorn/cloudflare-cache-cleaner.log
StandardError=append:/var/log/gunicorn/cloudflare-cache-cleaner-error.log

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
sys.path.insert(0, "/opt/Cloudflare-cache-cleaner")

bind = "127.0.0.1:8880"
workers = 2
timeout = 30
loglevel = "info"
wsgi_app = "cloudflare_cache_cleaner:application"

```
