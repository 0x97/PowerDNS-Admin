#!/usr/bin/env python

from migrate.versioning import api
from config import SQLALCHEMY_DATABASE_URI
from config import SQLALCHEMY_MIGRATE_REPO
from app import db
from app.models import Role, Setting, Language, Page
import os.path
import time
import sys

def start():
    wait_time = get_waittime_from_env()

    if not connect_db(wait_time):
        print("ERROR: Couldn't connect to database server")
        exit(1)

    init_records()

def get_waittime_from_env():
    return int(os.environ.get('WAITFOR_DB', 1))

def connect_db(wait_time):
    for i in xrange(0, wait_time):
        print("INFO: Wait for database server")
        sys.stdout.flush()
        try:
            db.create_all()
            return True
        except:
            time.sleep(1)

    return False

def init_roles(db, role_names):

    # Get key name of data
    name_of_roles = map(lambda r: r.name, role_names)

    # Query to get current data
    rows = db.session.query(Role).filter(Role.name.in_(name_of_roles)).all()
    name_of_rows = map(lambda r: r.name, rows)

    # Check which data that need to insert
    roles = filter(lambda r: r.name not in name_of_rows, role_names)

    # Insert data
    for role in roles:
        db.session.add(role)

def init_settings(db, setting_names):

    # Get key name of data
    name_of_settings = map(lambda r: r.name, setting_names)

    # Query to get current data
    rows = db.session.query(Setting).filter(Setting.name.in_(name_of_settings)).all()

    # Check which data that need to insert
    name_of_rows = map(lambda r: r.name, rows)
    settings = filter(lambda r: r.name not in name_of_rows, setting_names)

    # Insert data
    for setting in settings:
        db.session.add(setting)

def init_language(db, language_names):

    # Get key name of data
    name_of_languages = map(lambda r: r.name, language_names)

    # Query to get current data
    rows = db.session.query(Language).filter(Language.name.in_(name_of_languages)).all()

    # Check which data that need to insert
    name_of_rows = map(lambda r: r.name, rows)
    languages = filter(lambda r: r.name not in name_of_rows, language_names)

    # Insert data
    for language in languages:
        db.session.add(language)


def init_page(db, page_names):

    # Get key name of data
    name_of_pages = map(lambda r: r.name, page_names)

    # Query to get current data
    rows = db.session.query(Page).filter(Page.name.in_(name_of_pages)).all()

    # Check which data that need to insert
    name_of_rows = map(lambda r: r.name, rows)
    pages = filter(lambda r: r.name not in name_of_rows, page_names)

    # Insert data
    for page in pages:
        db.session.add(page)


def init_records():
    # Create initial user roles and turn off maintenance mode
    init_roles(db, [
        Role('Administrator', 'Administrator'),
        Role('User', 'User'),
        Role('Suspended', 'Suspended'),
        Role('Premium', 'Premium')
    ])
    init_settings(db, [
        Setting('alert_banner', 'False'),
        Setting('alert_banner_text', 'Alert'),
        Setting('maintenance', 'False'),
        Setting('fullscreen_layout', 'True'),
        Setting('record_helper', 'True'),
        Setting('login_ldap_first', 'False'),
        Setting('default_record_table_size', '30'),
        Setting('default_domain_table_size', '25'),
        Setting('auto_ptr','False'),
        Setting('css_skin', 'green'),
        Setting('background_pattern', 'default'),
        Setting('custom_language', 'False'),
        Setting('custom_pages', 'False'),
        Setting('site_name', '0x97-Admin'),
        Setting('signup_enabled', 'True'),
        Setting('admin_email', 'admin@example.com'),
        Setting('homepage_text', 'Change me in Global Settings'),
        Setting('user_domain_limit', '5'),
        Setting('user_domain_record_limit', 50),
        Setting('hide_login_otp', 'False'),
        Setting('hide_login_authtype', 'False'),
        Setting('enable_sidebar_quicklinks', 'False'),
        Setting('disable_wildcard_subdomain', 'True'),
        Setting('enable_user_customization', 'False')
    ])
    init_language(db, [
        Language('1', 'menu_dashboard_text', 'Dashboard'),
        Language('2', 'menu_about_text', 'About'),
        Language('3', 'menu_checkip_text', 'Check IP'),
        Language('4', 'menu_newdomain_text', 'New Domain'),
        Language('5', 'menu_adminconsole_text', 'Admin Console'),
        Language('6', 'menu_users_text', 'Users'),
        Language('7', 'menu_history_text', 'History'),
        Language('8', 'menu_globalsettings_text', 'Global Settings'),
        Language('9', 'menu_langsettings_text', 'Language Settings'),
        Language('10', 'menu_custompages_text', 'Custom Content'),
        Language('11', 'menu_login_text', 'Login'),
        Language('12', 'menu_register_text', 'Register'),
        Language('13', 'menu_header_account', 'ACCOUNT MENU'),
        Language('14', 'menu_header_custompages', 'SYSTEM PAGES'),
        Language('15', 'menu_header_user', 'USER MENU'),
        Language('16', 'menu_header_admin', 'ADMINISTRATION'),
        Language('17', 'menu_header_quicklinks', 'QUICK LINKS'),
        Language('18', 'sidebar_quicklinks', '<li><a href="http://0x97.io" target="_blank"><i class="fa fa-home"></i> <span>0x97.io</span></a></li>')
    ])
    init_page(db, [
        Page('1', 'Test', 'Test Page', 'test', 'fa fa-globe', 'User', 'True', 'Test page please ignore')
    ])

    db_commit = db.session.commit()
    commit_version_control(db_commit)

def commit_version_control(db_commit):
    if not os.path.exists(SQLALCHEMY_MIGRATE_REPO):
        api.create(SQLALCHEMY_MIGRATE_REPO, 'database repository')
        api.version_control(SQLALCHEMY_DATABASE_URI, SQLALCHEMY_MIGRATE_REPO)
    elif db_commit is not None:
        api.version_control(SQLALCHEMY_DATABASE_URI, SQLALCHEMY_MIGRATE_REPO, api.version(SQLALCHEMY_MIGRATE_REPO))

if __name__ == '__main__':
    start()
