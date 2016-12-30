# 0x97 PowerDNS-Admin
PowerDNS Administration portal, overhaul of ngoduykhanh/PowerDNS-Admin


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
 - Template selection options, with ability for users to customize appearance if admin enables customization
 - Background pattern/color/gradient options
 - Enhanced welcome/login screen
 - Custom language strings options
 - Mini-CMS feature for help/FAQ/etc pages
 - Users can add their own domains
 - Upgraded user permissions- admin can set limits on domains/records

## Setup

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

Homepage
![Homepage](http://i.imgur.com/Kvun0op.png)

User Dashboard
![User Dashboard](http://i.imgur.com/Gc4w36K.png)

Admin Dashboard
![Admin Dashboard](http://i.imgur.com/LOmYLmt.png)

Admin Settings
![Admin Settings](http://i.imgur.com/pt7nV96.png)

Custom Pages
![Custom Pages](http://i.imgur.com/yy0f6fA.png)

Page Editor
![Page Editor](http://i.imgur.com/ZzzQqvs.png)

User Management
![User Management](http://i.imgur.com/r059y1C.png)

User Theme Settings
![User Theme Settings](http://i.imgur.com/K9Z3EeZ.png)
