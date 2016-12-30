# 0x97 PowerDNS-Admin
PowerDNS Administration portal


#### Original Features:
- Multiple domain management
- Local / LDAP / Active Directory user authentication
- Support Two-factor authentication (TOTP)
- User management
- User access management based on domain
- User activity logging
- Dashboard and pdns service statistics
- DynDNS 2 protocol support
- Edit IPv6 PTRs using IPv6 addresses directly (no more editing of literal addresses!)
 
#### Added Features:
 - Template selection options
 - Background pattern/color/gradient options
 - Enhanced welcome/login screen
 - Custom template option with full settings
 - Custom language strings options
 - Upgraded user permissions- admin can set limits on domains/records
 - Ability to add and edit custom pages

## Setup

### Note:
To make development simpler, make sure to use the sqlite3 database `powerdnsadmin.db`. [A dev config.py is available here](https://git.omicroninteractive.com/0x97/powerdns-admin/snippets/4).

### PowerDNS Version Support:
PowerDNS-Admin supports PowerDNS autoritative server versions **3.4.2** and higher. 

### pdns Service
I assume that you have already installed powerdns service. Make sure that your `/etc/pdns/pdns.conf` has these contents

PowerDNS 4.0.0 and later
```
api=yes
api-key=your-powerdns-api-key
webserver=yes
```

PowerDNS before 4.0.0
```
experimental-json-interface=yes
experimental-api-key=your-powerdns-api-key
webserver=yes
```

This will enable API access in PowerDNS so PowerDNS-Admin can intergrate with PowerDNS.

### Create Database
We will create a database which used by this web application. Please note that this database is separate from the pdns database itself.

You could use any database that SQLAlchemy supports. For example, MySQL (you will need to `pip install MySQL-python` to use MySQL backend):
```
MariaDB [(none)]> CREATE DATABASE powerdnsadmin;

MariaDB [(none)]> GRANT ALL PRIVILEGES ON powerdnsadmin.* TO powerdnsadmin@'%' IDENTIFIED BY 'your-password';
```
For testing purpose, you could also use SQLite as backend. This way you do not have to install `MySQL-python` dependency. 
An SQLite database (with the latest migrations) and dev config are provided in the project root for this purpose.


### PowerDNS-Admin

In this installation guide, I am using Ubuntu and run the Python app with *virtualenv*. If you don't have it, lets install it:
```
$ sudo yum install python-pip
$ sudo pip install virtualenv
```

Additionally, make sure you have all the necessary dependencies installed (this is NOT necessary if using OS X).
```
sudo apt-get install build-essential python-dev libmysqlclient-dev python-mysqldb libsasl2-dev python-dev libldap2-dev libssl-dev
```

In your python web app directory, create a `flask` directory via `virtualenv`
```
$ virtualenv flask
```

Enable virtualenv and install python 3rd libraries
```
$ source ./flask/bin/activate
(flask)$ pip install -r requirements.txt
```

Web application configuration is stored in `config.py` file. Let's clone it from `config_template.py` file and then edit it
```
(flask)$ cp config_template.py config.py 
(flask)$ vim config.py
```

Create database after having proper configs
```
(flask)% ./create_db.py
```


Run the application and enjoy!
```
(flask)$ ./run.py
```

### Screenshots
![fullscreen-welcome](/uploads/88a350024cb5cd48257c9b623ae138dd/fullscreen-welcome.png)

![fullscreen-dashboard](/uploads/bd93ecb603c2a3e937fd39ca2e6673ca/fullscreen-dashboard.png)

![fullscreen-domaincreate](/uploads/3c2009e6f5d5ddb761726de3a5d81e31/fullscreen-domaincreate.png)

![fullscreen-custom-theme](/uploads/2b61017196dafa8609989c6ec04cf4fb/fullscreen-custom-theme.png)

![fullscreen-language-settings](/uploads/3069d929712f20ec8016ee299d498aa2/fullscreen-language-settings.png)

![fullscreen-settings](/uploads/e7a2e47a7cb74dc8bba27a1ddab3e2ac/fullscreen-settings.png)