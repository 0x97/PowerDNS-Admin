import base64
import json
import os
import traceback
import re
from distutils.util import strtobool
from distutils.version import StrictVersion
from functools import wraps
from io import BytesIO
import jinja2
import qrcode as qrc
import qrcode.image.svg as qrc_svg
from flask import g, request, make_response, jsonify, render_template, session, redirect, url_for, send_from_directory, abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug import secure_filename
from werkzeug.security import gen_salt
from .models import User, Domain, Record, Server, History, Anonymous, Setting, Language, DomainSetting, Page
from app import app, login_manager, github
from lib import utils

jinja2.filters.FILTERS['display_record_name'] = utils.display_record_name
jinja2.filters.FILTERS['display_master_name'] = utils.display_master_name
jinja2.filters.FILTERS['display_second_to_time'] = utils.display_time
jinja2.filters.FILTERS['email_to_gravatar_url'] = utils.email_to_gravatar_url

# Flag for pdns v4.x.x
# TODO: Find another way to do this
PDNS_VERSION = app.config['PDNS_VERSION']
if StrictVersion(PDNS_VERSION) >= StrictVersion('4.0.0'):
    NEW_SCHEMA = True
else:
    NEW_SCHEMA = False


def login():
    # these parameters will be needed in multiple paths
    LDAP_ENABLED = True if 'LDAP_TYPE' in app.config.keys() else False
    LOGIN_TITLE = app.config['LOGIN_TITLE'] if 'LOGIN_TITLE' in app.config.keys() else ''
    BASIC_ENABLED = app.config['BASIC_ENABLED']
    SIGNUP_ENABLED = app.config['SIGNUP_ENABLED']
    GITHUB_ENABLE = app.config.get('GITHUB_OAUTH_ENABLE')
    pages = Page.query.all()
    if g.user is not None and current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if 'github_token' in session:
        me = github.get('user')
        user_info = me.data
        user = User.query.filter_by(username=user_info['name']).first()
        if not user:
            # create user
            user = User(username=user_info['name'],
                        plain_text_password=gen_salt(7),
                        email=user_info['email'])
            user.create_local_user()
        session['user_id'] = user.id
        login_user(user, remember = False)
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        return render_template('home.html',
                               github_enabled=GITHUB_ENABLE,
                               ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE,
                               basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
    # process login
    username = request.form['username']
    password = request.form['password']
    otp_token = request.form.get('otptoken')
    auth_method = request.form.get('auth_method', 'LOCAL')
    # addition fields for registration case
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    email = request.form.get('email')
    rpassword = request.form.get('rpassword')
    if None in [firstname, lastname, email]:
        #login case
        remember_me = False
        if 'remember' in request.form:
            remember_me = True
        user = User(username=username, password=password, plain_text_password=password)
        try:
            auth = user.is_validate(method=auth_method)
            if auth == False:
                return render_template('home.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)
        except Exception, e:
            error = e.message['desc'] if 'desc' in e.message else e
            return render_template('home.html', error=error, ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)
        # check if user enabled OPT authentication
        if user.otp_secret:
            if otp_token:
                good_token = user.verify_totp(otp_token)
                if not good_token:
                    return render_template('home.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)
            else:
                return render_template('home.html', error='Token required', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)
        login_user(user, remember = remember_me)
        return redirect(request.args.get('next') or url_for('dashboard'))
    else:
        # registration case
        user = User(username=username, plain_text_password=password, firstname=firstname, lastname=lastname, email=email)
        # TODO: Move this into the JavaScript
        # validate password and password confirmation
        if password != rpassword:
            error = "Passsword and confirmation do not match"
            return render_template('register.html', error=error)
        try:
            result = user.create_local_user()
            if result == True:
                return render_template('home.html', username=username, password=password, ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED)
            else:
                return render_template('register.html', error=result)
        except Exception, e:
            error = e.message['desc'] if 'desc' in e.message else e
            return render_template('register.html', error=error)

# BEGIN Global Settings: Configure at /admin/settings
@app.context_processor
def inject_admin_email_setting():
    admin_email_setting = Setting.query.filter(Setting.name == 'admin_email').first()
    return dict(admin_email_setting=admin_email_setting.value)
@app.context_processor
def inject_alert_banner_setting():
    alert_banner_setting = Setting.query.filter(Setting.name == 'alert_banner').first()
    return dict(alert_banner_setting=strtobool(alert_banner_setting.value))
@app.context_processor
def inject_alert_banner_text_setting():
    alert_banner_text_setting = Setting.query.filter(Setting.name == 'alert_banner_text').first()
    return dict(alert_banner_text_setting=alert_banner_text_setting.value)
@app.context_processor
def inject_auto_ptr_setting():
    auto_ptr_setting = Setting.query.filter(Setting.name == 'auto_ptr').first()
    return dict(auto_ptr_setting=strtobool(auto_ptr_setting.value))
@app.context_processor
def inject_background_pattern_setting():
    background_pattern_setting = Setting.query.filter(Setting.name == 'background_pattern').first()
    return dict(background_pattern_setting=background_pattern_setting.value)
@app.context_processor
def inject_css_skin_setting():
    css_skin_setting = Setting.query.filter(Setting.name == 'css_skin').first()
    return dict(css_skin_setting=css_skin_setting.value)
# TODO: Figure out why jinja2 is only rendering the first record in the language table...
@app.context_processor
def inject_custom_language_setting():
    custom_language_setting = Setting.query.filter(Setting.name == 'custom_language').first()
    return dict(custom_language_setting=strtobool(custom_language_setting.value))
@app.context_processor
def inject_custom_pages_setting():
    custom_pages_setting = Setting.query.filter(Setting.name == 'custom_pages').first()
    return dict(custom_pages_setting=strtobool(custom_pages_setting.value))
@app.context_processor
def inject_default_domain_table_size_setting():
    default_domain_table_size_setting = Setting.query.filter(Setting.name == 'default_domain_table_size').first()
    return dict(default_domain_table_size_setting=default_domain_table_size_setting.value)
@app.context_processor
def inject_default_record_table_size_setting():
    default_record_table_size_setting = Setting.query.filter(Setting.name == 'default_record_table_size').first()
    return dict(default_record_table_size_setting=default_record_table_size_setting.value)
@app.context_processor
def inject_disable_wildcard_subdomain_setting():
    disable_wildcard_subdomain_setting = Setting.query.filter(Setting.name == 'disable_wildcard_subdomain').first()
    return dict(disable_wildcard_subdomain_setting=strtobool(disable_wildcard_subdomain_setting.value))
@app.context_processor
def inject_enable_sidebar_quicklinks_setting():
    enable_sidebar_quicklinks_setting = Setting.query.filter(Setting.name == 'enable_sidebar_quicklinks').first()
    return dict(enable_sidebar_quicklinks_setting=strtobool(enable_sidebar_quicklinks_setting.value))
@app.context_processor
def inject_enable_user_customization_setting():
    enable_user_customization_setting = Setting.query.filter(Setting.name == 'enable_user_customization').first()
    return dict(enable_user_customization_setting=strtobool(enable_user_customization_setting.value))
@app.context_processor
def inject_fullscreen_layout_setting():
    fullscreen_layout_setting = Setting.query.filter(Setting.name == 'fullscreen_layout').first()
    return dict(fullscreen_layout_setting=strtobool(fullscreen_layout_setting.value))
@app.context_processor
def inject_hide_login_authtype_setting():
    hide_login_authtype_setting = Setting.query.filter(Setting.name == 'hide_login_authtype').first()
    return dict(hide_login_authtype_setting=strtobool(hide_login_authtype_setting.value))
@app.context_processor
def inject_hide_login_otp_setting():
    hide_login_otp_setting = Setting.query.filter(Setting.name == 'hide_login_otp').first()
    return dict(hide_login_otp_setting=strtobool(hide_login_otp_setting.value))
@app.context_processor
def inject_homepage_text_setting():
    homepage_text_setting = Setting.query.filter(Setting.name == 'homepage_text').first()
    return dict(homepage_text_setting=homepage_text_setting.value)
@app.context_processor
def inject_login_ldap_first_setting():
    login_ldap_first_setting = Setting.query.filter(Setting.name == 'login_ldap_first').first()
    return dict(login_ldap_first_setting=strtobool(login_ldap_first_setting.value))
@app.context_processor
def inject_record_helper_setting():
    record_helper_setting = Setting.query.filter(Setting.name == 'record_helper').first()
    return dict(record_helper_setting=strtobool(record_helper_setting.value))
@app.context_processor
def inject_signup_enabled_setting():
    signup_enabled_setting = Setting.query.filter(Setting.name == 'signup_enabled').first()
    return dict(signup_enabled_setting=strtobool(signup_enabled_setting.value))
@app.context_processor
def inject_site_name_setting():
    site_name_setting = Setting.query.filter(Setting.name == 'site_name').first()
    return dict(site_name_setting=site_name_setting.value)
@app.context_processor
def inject_user_domain_limit_setting():
    user_domain_limit_setting = Setting.query.filter(Setting.name == 'user_domain_limit').first()
    return dict(user_domain_limit_setting=user_domain_limit_setting.value)
@app.context_processor
def inject_user_domain_record_limit_setting():
    user_domain_record_limit_setting = Setting.query.filter(Setting.name == 'user_domain_record_limit').first()
    return dict(user_domain_record_limit_setting=user_domain_record_limit_setting.value)
# END Global Settings

# BEGIN Language Settings: Configure at /admin/language_settings
@app.context_processor
def inject_menu_dashboard_text():
    menu_dashboard_text_language = Language.query.filter(Language.name == 'menu_dashboard_text').first()
    return dict(menu_dashboard_text_language=menu_dashboard_text_language.value)
@app.context_processor
def inject_menu_about_text():
    menu_about_text_language = Language.query.filter(Language.name == 'menu_about_text').first()
    return dict(menu_about_text_language=menu_about_text_language.value)
@app.context_processor
def inject_menu_checkip_text():
    menu_checkip_text_language = Language.query.filter(Language.name == 'menu_checkip_text').first()
    return dict(menu_checkip_text_language=menu_checkip_text_language.value)
@app.context_processor
def inject_menu_newdomain_text():
    menu_newdomain_text_language = Language.query.filter(Language.name == 'menu_newdomain_text').first()
    return dict(menu_newdomain_text_language=menu_newdomain_text_language.value)
@app.context_processor
def inject_menu_adminconsole_text():
    menu_adminconsole_text_language = Language.query.filter(Language.name == 'menu_adminconsole_text').first()
    return dict(menu_adminconsole_text_language=menu_adminconsole_text_language.value)
@app.context_processor
def inject_menu_users_text():
    menu_users_text_language = Language.query.filter(Language.name == 'menu_users_text').first()
    return dict(menu_users_text_language=menu_users_text_language.value)
@app.context_processor
def inject_menu_history_text():
    menu_history_text_language = Language.query.filter(Language.name == 'menu_history_text').first()
    return dict(menu_history_text_language=menu_history_text_language.value)
@app.context_processor
def inject_menu_globalsettings_text():
    menu_globalsettings_text_language = Language.query.filter(Language.name == 'menu_globalsettings_text').first()
    return dict(menu_globalsettings_text_language=menu_globalsettings_text_language.value)
@app.context_processor
def inject_menu_langsettings_text():
    menu_langsettings_text_language = Language.query.filter(Language.name == 'menu_langsettings_text').first()
    return dict(menu_langsettings_text_language=menu_langsettings_text_language.value)
@app.context_processor
def inject_menu_custompages_text():
    menu_custompages_text_language = Language.query.filter(Language.name == 'menu_custompages_text').first()
    return dict(menu_custompages_text_language=menu_custompages_text_language.value)
@app.context_processor
def inject_menu_login_text():
    menu_login_text_language = Language.query.filter(Language.name == 'menu_login_text').first()
    return dict(menu_login_text_language=menu_login_text_language.value)
@app.context_processor
def inject_menu_register_text():
    menu_register_text_language = Language.query.filter(Language.name == 'menu_register_text').first()
    return dict(menu_register_text_language=menu_register_text_language.value)
@app.context_processor
def inject_menu_header_account():
    menu_header_account = Language.query.filter(Language.name == 'menu_header_account').first()
    return dict(menu_header_account=menu_header_account.value)
@app.context_processor
def inject_menu_header_custompages():
    menu_header_custompages = Language.query.filter(Language.name == 'menu_header_custompages').first()
    return dict(menu_header_custompages=menu_header_custompages.value)
@app.context_processor
def inject_menu_header_user():
    menu_header_user = Language.query.filter(Language.name == 'menu_header_user').first()
    return dict(menu_header_user=menu_header_user.value)
@app.context_processor
def inject_menu_header_admin():
    menu_header_admin = Language.query.filter(Language.name == 'menu_header_admin').first()
    return dict(menu_header_admin=menu_header_admin.value)
@app.context_processor
def inject_menu_header_quicklinks():
    menu_header_quicklinks = Language.query.filter(Language.name == 'menu_header_quicklinks').first()
    return dict(menu_header_quicklinks=menu_header_quicklinks.value)

@app.context_processor
def inject_sidebar_quicklinks():
    sidebar_quicklinks = Language.query.filter(Language.name == 'sidebar_quicklinks').first()
    return dict(sidebar_quicklinks=sidebar_quicklinks.value)
# END Language Settings

# BEGIN User Customization Settings
# @app.context_processor
# def inject_user_css_skin():
#     user_css_skin = User.query.filter(User.css_skin == 'css_skin').first()
#     return dict(user_css_skin=current_user.css_skin.value)

# START USER AUTHENTICATION HANDLER
@app.before_request
def before_request():
    # check site maintenance mode first
    maintenance = Setting.query.filter(Setting.name == 'maintenance').first()
    if maintenance and maintenance.value == 'True':
        return render_template('maintenance.html')
    # check if user is anonymous
    g.user = current_user
    login_manager.anonymous_user = Anonymous

@login_manager.user_loader
def load_user(id):
    """
    This will be current_user
    """
    return User.query.get(int(id))
def dyndns_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated is False:
            return render_template('dyndns.html', response='badauth'), 200
        return f(*args, **kwargs)
    return decorated_function
@login_manager.request_loader
def login_via_authorization_header(request):
    auth_header = request.headers.get('Authorization')
    if auth_header:
        auth_header = auth_header.replace('Basic ', '', 1)
        try:
            auth_header = base64.b64decode(auth_header)
            username,password = auth_header.split(":")
        except TypeError, e:
            error = e.message['desc'] if 'desc' in e.message else e
            return None
        user = User(username=username, password=password, plain_text_password=password)
        try:
            auth = user.is_validate(method='LOCAL')
            if auth == False:
                return None
            else:
                login_user(user, remember = False)
                return user
        except Exception, e:
            return None
    return None
# END USER AUTHENTICATION HANDLER

# START CUSTOMIZE DECORATOR
def admin_role_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user.role.name != 'Administrator':
            return redirect(url_for('error', code=401))
        return f(*args, **kwargs)
    return decorated_function
# END CUSTOMIZE DECORATOR

# START VIEWS
@app.errorhandler(400)
def http_bad_request(e):
    return redirect(url_for('error', code=400))
@app.errorhandler(401)
def http_unauthorized(e):
    return redirect(url_for('error', code=401))
@app.errorhandler(404)
def http_internal_server_error(e):
    return redirect(url_for('error', code=404))
@app.errorhandler(500)
def http_page_not_found(e):
    return redirect(url_for('error', code=500))
@app.route('/error/<string:code>', methods=['GET', 'POST'])
def error(code, msg=None):
    pages = Page.query.all()
    login()
    if request.method == 'POST':
        print traceback.format_exc()
        return redirect(url_for('dashboard'))
    supported_code = ('400', '401', '404', '500')
    if code in supported_code:
        # log a traceback of an error
        print traceback.format_exc()
        return render_template('errors/%s.html' % code, msg=msg, pages=pages), int(code)
    else:
        return render_template('errors/404.html'), 404

# Show custom pages
@app.route('/<string:page>', methods=['GET', 'POST'])
@login_manager.unauthorized_handler
def custompage(page):
    login()
    pages = Page.query.all()
    if request.method == 'POST':
        return redirect(url_for('dashboard'))
    page = Page.query.filter(Page.url == page).first()
    return render_template('page.html', page=page, pages=pages)

# User registration - can be disabled in Global Settings
@app.route('/register', methods=['GET'])
def register():
    pages = Page.query.all()
    SIGNUP_ENABLED = app.config['SIGNUP_ENABLED']
    if SIGNUP_ENABLED:
        return render_template('register.html', pages=pages)
    else:
        return render_template('errors/404.html', pages=pages), 404

# Github login
@app.route('/github/login')
def github_login():
    pages = Page.query.all()
    if not app.config.get('GITHUB_OAUTH_ENABLE'):
        return abort(400)
    return github.authorize(callback=url_for('authorized', _external=True))

# Login page- obsolete
# TODO: Remove obsolete login page after verifying that it is safe to do so
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login()

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('github_token', None)
    logout_user()
    return redirect(url_for('home'))

# User dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    d = Domain().update()
    if current_user.role.name == 'Administrator':
        domains = Domain.query.all()
    else:
        domains = User(id=current_user.id).get_domain()
    # stats for dashboard
    domain_count = Domain.query.count()
    users = User.query.all()
    user = User(id=current_user.id)
    history_number = History.query.count()
    history = History.query.order_by(History.created_on.desc()).limit(4)
    server = Server(server_id='localhost')
    statistics = server.get_statistic()
    pages = Page.query.all()
    if statistics:
        uptime = filter(lambda uptime: uptime['name'] == 'uptime', statistics)[0]['value']
    else:
        uptime = 0
    return render_template('dashboard.html', domains=domains, domain_count=domain_count, users=users, history_number=history_number, user=user, uptime=uptime, histories=history, pages=pages)


# Domain route: list and edit zones
@app.route('/domain/<path:domain_name>', methods=['GET', 'POST'])
@login_required
def domain(domain_name):
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    r = Record()
    domain = Domain.query.filter(Domain.name == domain_name).first()
    if domain:
        # query domain info from PowerDNS API
        zone_info = r.get_record_data(domain.name)
        if zone_info:
            jrecords = zone_info['records']
        else:
            # can not get any record, API server might be down
            return redirect(url_for('error', code=500))
        records = []
        #TODO: This should be done in the "model" instead of "view"
        if NEW_SCHEMA:
            for jr in jrecords:
                if jr['type'] in app.config['RECORDS_ALLOW_EDIT']:
                    for subrecord in jr['records']:
                        record = Record(name=jr['name'], type=jr['type'], status='Disabled' if subrecord['disabled'] else 'Active', ttl=jr['ttl'], data=subrecord['content'])
                        records.append(record)
        else:
            for jr in jrecords:
                if jr['type'] in app.config['RECORDS_ALLOW_EDIT']:
                    record = Record(name=jr['name'], type=jr['type'], status='Disabled' if jr['disabled'] else 'Active', ttl=jr['ttl'], data=jr['content'])
                    records.append(record)
        if not re.search('ip6\.arpa|in-addr\.arpa$', domain_name):
            editable_records = app.config['RECORDS_ALLOW_EDIT']
        else:
            editable_records = ['PTR']
        return render_template('domain.html', domain=domain, records=records, editable_records=editable_records, pages=pages)
    else:
        return redirect(url_for('error', code=404))

# Add domains as normal user
# TODO: assign user permission to domains they add
@app.route('/user/domain/add', methods=['GET', 'POST'])
@login_required
def user_domain_add():
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            domain_name = request.form.getlist('domain_name')[0]
            domain_type = request.form.getlist('radio_type')[0]
            soa_edit_api = request.form.getlist('radio_type_soa_edit_api')[0]
            if ' ' in domain_name or not domain_name or not domain_type:
                return render_template('errors/400.html', msg="Please correct your input", pages=pages), 400
            if domain_type == 'slave':
                if request.form.getlist('domain_master_address'):
                    domain_master_string = request.form.getlist('domain_master_address')[0]
                    domain_master_string = domain_master_string.replace(' ','')
                    domain_master_ips = domain_master_string.split(',')
            else:
                domain_master_ips = []
            d = Domain()
            result = d.add(domain_name=domain_name, domain_type=domain_type, soa_edit_api=soa_edit_api)
            if result['status'] == 'ok':
                d = Domain(name=domain_name)
                # query PowerDNS for the new domain, go ahead and load it into the app's DB
                Domain.update(d)
                Domain.query.all()
                # log the new domain in history
                history = History(msg='Add domain %s' % domain_name, detail=str({'domain_type': domain_type, 'domain_master_ips': domain_master_ips}), created_by=current_user.username)
                history.add()
                # add the user to their domain
                d = Domain(name=domain_name)
                # create a list with the user's username, as required by the grant_privileges function
                ul = [ current_user.username ]
                new_user_list = ul
                d.grant_privielges(new_user_list)
                return redirect(url_for('dashboard'))
            else:
                return render_template('errors/400.html', msg=result['msg'], pages=pages), 400
        except:
            print traceback.format_exc()
            return redirect(url_for('error', code=500))
    d = Domain().update()
    if current_user.role.name == 'Administrator':
        domains = Domain.query.all()
    else:
        domains = User(id=current_user.id).get_domain()
    # stats for dashboard
    domain_count = Domain.query.count()
    return render_template('user_domain_add.html', domains=domains, domain_count=domain_count, pages=pages)

# Delete user domains
@app.route('/user/domain/<string:domain_name>/delete', methods=['GET'])
@login_required
def user_domain_delete(domain_name):
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    # Define variables that help us determine domain permissions
    domain = Domain.query.filter(Domain.name == domain_name).first()
    domains = User(id=current_user.id).get_domain()
    d = Domain()
    # check if the user has permissions for domain
    if domain in domains:
        result = d.delete(domain_name)
        history = History(msg='Delete domain %s' % domain_name, created_by=current_user.username)
        history.add()
        if result['status'] == 'error':
            return redirect(url_for('error', code=500))
    # log a history message when users try to delete unauthorized domains
    else:
        history = History(msg='User attempted to delete domain without permission: %s' % domain_name, created_by=current_user.username)
        history.add()
        return redirect(url_for('error', code=401))

    return redirect(url_for('dashboard'))

# Manage domain settings
@app.route('/user/domain/<string:domain_name>/managesetting', methods=['GET', 'POST'])
@login_required
def user_setdomainsetting(domain_name):
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'set_setting', 'setting': 'default_action, 'value': 'True'}
        #
        try:
            pdata = request.data
            jdata = json.loads(pdata)
            data = jdata['data']
            if jdata['action'] == 'set_setting':
                new_setting = data['setting']
                new_value = str(data['value'])
                domain = Domain.query.filter(Domain.name == domain_name).first()
                setting = DomainSetting.query.filter(DomainSetting.domain == domain).filter(DomainSetting.setting == new_setting).first()
                if setting:
                    if setting.set(new_value):
                        history = History(msg='Setting %s changed value to %s for %s' % (new_setting, new_value, domain.name), created_by=current_user.username)
                        history.add()
                        return make_response(jsonify( { 'status': 'ok', 'msg': 'Setting updated.' } ))
                    else:
                        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to set value of setting.' } ))
                else:
                    if domain.add_setting(new_setting, new_value):
                        history = History(msg='New setting %s with value %s for %s has been created' % (new_setting, new_value, domain.name), created_by=current_user.username)
                        history.add()
                        return make_response(jsonify( { 'status': 'ok', 'msg': 'New setting created and updated.' } ))
                    else:
                        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to create new setting.' } ))
            else:
                return make_response(jsonify( { 'status': 'error', 'msg': 'Action not supported.' } ), 400)
        except:
            print traceback.format_exc()
            return make_response(jsonify( { 'status': 'error', 'msg': 'There is something wrong, please contact Administrator.' } ), 400)

# Manage domain settings
@app.route('/user/domain/<string:domain_name>/manage', methods=['GET', 'POST'])
@login_required
def user_domain_management(domain_name):
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if not domain:
            return redirect(url_for('error', code=404))
        users = User.query.all()
        # get list of user ids to initilize selection data
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()
        return render_template('user_domain_management.html', domain=domain, users=users, domain_user_ids=domain_user_ids, pages=pages)
    if request.method == 'POST':
        # username in right column
        new_user_list = request.form.getlist('domain_multi_user[]')
        # get list of user ids to compare
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()
        # grant/revoke user privielges
        d.grant_privielges(new_user_list)
        history = History(msg='Change domain %s access control' % domain_name, detail=str({'user_has_access': new_user_list}), created_by=current_user.username)
        history.add()
        return redirect(url_for('domain_management', domain_name=domain_name))


# Administrative domain add
@app.route('/admin/domain/add', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domain_add():
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            domain_name = request.form.getlist('domain_name')[0]
            domain_type = request.form.getlist('radio_type')[0]
            soa_edit_api = request.form.getlist('radio_type_soa_edit_api')[0]
            if ' ' in domain_name or not domain_name or not domain_type:
                return render_template('errors/400.html', msg="Please correct your input", pages=pages), 400
            if domain_type == 'slave':
                if request.form.getlist('domain_master_address'):
                    domain_master_string = request.form.getlist('domain_master_address')[0]
                    domain_master_string = domain_master_string.replace(' ','')
                    domain_master_ips = domain_master_string.split(',')
            else:
                domain_master_ips = []
            d = Domain()
            result = d.add(domain_name=domain_name, domain_type=domain_type, soa_edit_api=soa_edit_api, domain_master_ips=domain_master_ips)
            if result['status'] == 'ok':
                history = History(msg='Add domain %s' % domain_name, detail=str({'domain_type': domain_type, 'domain_master_ips': domain_master_ips}), created_by=current_user.username)
                history.add()
                return redirect(url_for('dashboard'))
            else:
                return render_template('errors/400.html', msg=result['msg'], pages=pages), 400
        except:
            return redirect(url_for('error', code=500))
    return render_template('domain_add.html', pages=pages)

# DNS Admin Content Management Routes
# 2016 0x97

# List custom pages
@app.route('/admin/page')
@login_required
@admin_role_required
def custom_pages():
    pages = Page.query.all()
    return render_template('custom-pages.html', pages=pages)

# Add new page
@app.route('/admin/page/add', methods=['GET', 'POST'])
@login_required
@admin_role_required
def page_add():
    pages = Page.query.all()
    if request.method == 'POST':
        try:
            page_name = request.form.getlist('page_name')[0]
            page_title = request.form.getlist('page_title')[0]
            page_url = request.form.getlist('page_url')[0]
            page_icon = request.form.getlist('page_icon')[0]
            page_roles = request.form.getlist('page_roles')[0]
            page_published = request.form.getlist('page_published')[0]
            page_content = request.form.getlist('page_content')[0]
            if ' ' in page_name or not page_name or not page_title:
                return render_template('errors/400.html', msg="Please make sure you have filled out all fields.", pages=pages), 400
            p = Page()
            result = p.addpage(page_name=page_name, page_title=page_title, page_url=page_url, page_icon=page_icon, page_roles=page_roles, page_published=page_published, page_content=page_content)
            if result['status'] == 'ok':
                history = History(msg='Custom page %s' % page_name, created_by=current_user.username)
                history.add()
                return redirect(url_for('custom_pages'))

        except:
            print traceback.format_exc()
            return redirect(url_for('error', code=500))
    return render_template ('custompage_add.html', pages=pages)

# Delete page
@app.route('/admin/page/<string:page_id>/delete', methods=['GET', 'POST'])
@login_required
@admin_role_required
def page_delete(page_id):
    p = Page()
    result = p.delete(page_id)
    if result['status'] == 'error':
        print traceback.format_exc()
        return redirect(url_for('error', code=500))
    if result['status'] == 'ok':
        history = History(msg='Delete page %s' % page_id, created_by=current_user.username)
        history.add()
        return redirect(url_for('custom_pages'))
    return redirect(url_for('custom_pages'))

# Manage page metadata and content
@app.route('/admin/page/<string:page_id>/manage', methods=['GET', 'POST'])
@login_required
@admin_role_required
def page_manage(page_id):
    pages = Page.query.all()
    p = Page()
    page = Page.query.filter(Page.id == page_id).first()
    if request.method == 'GET':
        settings = Page.query.filter(Page.id != 'maintenance')
        return render_template('custompage_manage.html', settings=settings, pages=pages, page=page)

# Apply page changes
@app.route('/admin/page/<string:page_id>/manage/apply', methods=['POST'])
@login_required
@admin_role_required
def page_apply(page_id):
    page = Page.query.filter(Page.id == page_id).first()
    if request.method == 'POST':
        try:
            page_id = page_id
            page_name = request.form.getlist('page_name')[0]
            page_title = request.form.getlist('page_title')[0]
            page_url = request.form.getlist('page_url')[0]
            page_icon = request.form.getlist('page_icon')[0]
            page_roles = request.form.getlist('page_roles')[0]
            page_published = request.form.getlist('page_published')[0]
            page_content = request.form.getlist('page_content')[0]

            if ' ' in page_id or not page_id or not page_title:
                return render_template('errors/400.html', msg="Please make sure you have filled out all fields.", pages=pages), 400

            p = Page()
            result = p.apply(page_id=page_id, page_name=page_name, page_title=page_title, page_url=page_url, page_icon=page_icon, page_roles=page_roles, page_published=page_published, page_content=page_content)
            if result['status'] == 'ok':
                history = History(msg='Edited custom page %s' % page_title, created_by=current_user.username)
                history.add()
                return redirect(url_for('custom_pages'))

        except:
            print traceback.format_exc()
            return redirect(url_for('error', code=500))
    return render_template ('custompage_manage.html', pages=pages, page=page)

# Admin: domain deletion
@app.route('/admin/domain/<string:domain_name>/delete', methods=['GET'])
@login_required
@admin_role_required
def domain_delete(domain_name):
    d = Domain()
    result = d.delete(domain_name)
    if result['status'] == 'error':
        return redirect(url_for('error', code=500))
    history = History(msg='Delete domain %s' % domain_name, created_by=current_user.username)
    history.add()
    return redirect(url_for('dashboard'))

# Admin: domain management
@app.route('/admin/domain/<string:domain_name>/manage', methods=['GET', 'POST'])
@login_required
@admin_role_required
def domain_management(domain_name):
    pages = Page.query.all()
    if request.method == 'GET':
        domain = Domain.query.filter(Domain.name == domain_name).first()
        if not domain:
            return redirect(url_for('error', code=404))
        users = User.query.all()
        # get list of user ids to initilize selection data
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()
        return render_template('domain_management.html', domain=domain, users=users, domain_user_ids=domain_user_ids, pages=pages)
    if request.method == 'POST':
        # username in right column
        new_user_list = request.form.getlist('domain_multi_user[]')
        # get list of user ids to compare
        d = Domain(name=domain_name)
        domain_user_ids = d.get_user()
        # grant/revoke user privielges
        d.grant_privielges(new_user_list)
        history = History(msg='Change domain %s access control' % domain_name, detail=str({'user_has_access': new_user_list}), created_by=current_user.username)
        history.add()
        return redirect(url_for('domain_management', domain_name=domain_name))

# Apply domain changes
@app.route('/domain/<string:domain_name>/apply', methods=['POST'], strict_slashes=False)
@login_required
def record_apply(domain_name):
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    """
    example jdata: {u'record_ttl': u'1800', u'record_type': u'CNAME', u'record_name': u'test4', u'record_status': u'Active', u'record_data': u'duykhanh.me'}
    """
    #TODO: filter removed records / name modified records.
    try:
        pdata = request.data
        jdata = json.loads(pdata)
        r = Record()
        result = r.apply(domain_name, jdata)
        if result['status'] == 'ok':
            history = History(msg='Apply record changes to domain %s' % domain_name, detail=str(jdata), created_by=current_user.username)
            history.add()
            return make_response(jsonify( result ), 200)
        else:
            return make_response(jsonify( result ), 400)
    except:
        print traceback.format_exc()
        return make_response(jsonify( {'status': 'error', 'msg': 'Error when applying new changes'} ), 500)

# Update domain
@app.route('/domain/<string:domain_name>/update', methods=['POST'], strict_slashes=False)
@login_required
def record_update(domain_name):
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    """
    This route is used for domain work as Slave Zone only
    Pulling the records update from its Master
    """
    try:
        pdata = request.data
        jdata = json.loads(pdata)
        domain_name = jdata['domain']
        d = Domain()
        result = d.update_from_master(domain_name)
        if result['status'] == 'ok':
            return make_response(jsonify( {'status': 'ok', 'msg': result['msg']} ), 200)
        else:
            return make_response(jsonify( {'status': 'error', 'msg': result['msg']} ), 500)
    except:
        print traceback.format_exc()
        return make_response(jsonify( {'status': 'error', 'msg': 'Error when applying new changes'} ), 500)

# Delete domain records
@app.route('/domain/<string:domain_name>/record/<string:record_name>/type/<string:record_type>/delete', methods=['GET'])
@login_required
@admin_role_required
def record_delete(domain_name, record_name, record_type):
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    try:
        r = Record(name=record_name, type=record_type)
        result = r.delete(domain=domain_name)
        if result['status'] == 'error':
            print result['msg']
    except:
        print traceback.format_exc()
        return redirect(url_for('error', code=500)), 500
    return redirect(url_for('domain', domain_name=domain_name))

# DNSSEC modal data
@app.route('/domain/<string:domain_name>/dnssec', methods=['GET'])
@login_required
def domain_dnssec(domain_name):
    domain = Domain()
    dnssec = domain.get_domain_dnssec(domain_name)
    return make_response(jsonify(dnssec), 200)

# Allow creation of record via DynDNS
# TODO: Make sure users can only change setting on their own domain
@app.route('/domain/<string:domain_name>/managesetting', methods=['GET', 'POST'])
@login_required
def admin_setdomainsetting(domain_name):
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'set_setting', 'setting': 'default_action, 'value': 'True'}
        #
        try:
            pdata = request.data
            jdata = json.loads(pdata)
            data = jdata['data']
            if jdata['action'] == 'set_setting':
                new_setting = data['setting']
                new_value = str(data['value'])
                domain = Domain.query.filter(Domain.name == domain_name).first()
                setting = DomainSetting.query.filter(DomainSetting.domain == domain).filter(DomainSetting.setting == new_setting).first()
                if setting:
                    if setting.set(new_value):
                        history = History(msg='Setting %s changed value to %s for %s' % (new_setting, new_value, domain.name), created_by=current_user.username)
                        history.add()
                        return make_response(jsonify( { 'status': 'ok', 'msg': 'Setting updated.' } ))
                    else:
                        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to set value of setting.' } ))
                else:
                    if domain.add_setting(new_setting, new_value):
                        history = History(msg='New setting %s with value %s for %s has been created' % (new_setting, new_value, domain.name), created_by=current_user.username)
                        history.add()
                        return make_response(jsonify( { 'status': 'ok', 'msg': 'New setting created and updated.' } ))
                    else:
                        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to create new setting.' } ))
            else:
                return make_response(jsonify( { 'status': 'error', 'msg': 'Action not supported.' } ), 400)
        except:
            print traceback.format_exc()
            return make_response(jsonify( { 'status': 'error', 'msg': 'There is something wrong, please contact Administrator.' } ), 400)

# Admin console
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin():
    pages = Page.query.all()
    domains = Domain.query.all()
    users = User.query.all()
    server = Server(server_id='localhost')
    configs = server.get_config()
    statistics = server.get_statistic()
    history_number = History.query.count()
    if statistics:
        uptime = filter(lambda uptime: uptime['name'] == 'uptime', statistics)[0]['value']
    else:
        uptime = 0
    return render_template('admin.html', pages=pages, domains=domains, users=users, configs=configs, statistics=statistics, uptime=uptime, history_number=history_number)

# Admin: add new user
@app.route('/admin/user/create', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_createuser():
    pages = Page.query.all()
    if request.method == 'GET':
        return render_template('admin_createuser.html', pages=pages)
    if request.method == 'POST':
        fdata = request.form
        user = User(username=fdata['username'], plain_text_password=fdata['password'], firstname=fdata['firstname'], lastname=fdata['lastname'], email=fdata['email'])
        if fdata['password'] == "":
            return render_template('admin_createuser.html', user=user, blank_password=True, pages=pages)
        result = user.create_local_user();
        if result == 'Email already existed':
            return render_template('admin_createuser.html', user=user, duplicate_email=True, pages=pages)
        if result == 'Username already existed':
            return render_template('admin_createuser.html', user=user, duplicate_username=True, pages=pages)
        return redirect(url_for('admin_manageuser'))

# Admin: manage user
@app.route('/admin/manageuser', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_manageuser():
    pages = Page.query.all()
    if request.method == 'GET':
        users = User.query.order_by(User.username).all()
        return render_template('admin_manageuser.html', users=users, pages=pages)
    if request.method == 'POST':
        #
        # post data should in format
        # {'action': 'delete_user', 'data': 'username'}
        #
        try:
            pdata = request.data
            jdata = json.loads(pdata)
            data = jdata['data']
            # delete user
            if jdata['action'] == 'delete_user':
                user = User(username=data)
                result = user.delete()
                if result:
                    history = History(msg='Delete username %s' % data, created_by=current_user.username)
                    history.add()
                    return make_response(jsonify( { 'status': 'ok', 'msg': 'User has been removed.' } ), 200)
                else:
                    return make_response(jsonify( { 'status': 'error', 'msg': 'Cannot remove user.' } ), 500)
            # drop user privileges
            elif jdata['action'] == 'revoke_user_privielges':
                user = User(username=data)
                result = user.revoke_privilege()
                if result:
                    history = History(msg='Revoke %s user privielges' % data, created_by=current_user.username)
                    history.add()
                    return make_response(jsonify( { 'status': 'ok', 'msg': 'Revoked user privielges.' } ), 200)
                else:
                    print traceback.format_exc()
                    return make_response(jsonify( { 'status': 'error', 'msg': 'Cannot revoke user privilege.' } ), 500)
            # set user as administrator
            elif jdata['action'] == 'set_admin':
                username = data['username']
                is_admin = data['is_admin']
                user = User(username=username)
                result = user.set_admin(is_admin)
                if result:
                    history = History(msg='Change user role of %s' % username, created_by=current_user.username)
                    history.add()
                    return make_response(jsonify( { 'status': 'ok', 'msg': 'Changed user role successfully.' } ), 200)
                else:
                    print traceback.format_exc()
                    return make_response(jsonify( { 'status': 'error', 'msg': 'Cannot change user role.' } ), 500)

            # set user as premium/unset
            # premium users are exempt from all limitations and restrictions: use this role carefully
            elif jdata['action'] == 'set_premium':
                username = data['username']
                is_premium = data['is_premium']
                user = User(username=username)
                result = user.set_premium(is_premium)
                if result:
                    history = History(msg='Change user role of %s' % username, created_by=current_user.username)
                    history.add()
                    return make_response(jsonify( { 'status': 'ok', 'msg': 'Changed user role successfully.' } ), 200)
                else:
                    print traceback.format_exc()
                    return make_response(jsonify( { 'status': 'error', 'msg': 'Cannot change user role.' } ), 500)

            # suspend/unsuspend user
            elif jdata['action'] == 'set_suspended':
                username = data['username']
                is_suspended = data['is_suspended']
                user = User(username=username)
                result = user.set_suspended(is_suspended)
                if result:
                    history = History(msg='Change user role of %s' % username, created_by=current_user.username)
                    history.add()
                    return make_response(jsonify( { 'status': 'ok', 'msg': 'Changed user role successfully.' } ), 200)
                else:
                    print traceback.format_exc()
                    return make_response(jsonify( { 'status': 'error', 'msg': 'Cannot change user role.' } ), 500)
            else:
                return make_response(jsonify( { 'status': 'error', 'msg': 'Action not supported.' } ), 400)
        except:
            print traceback.format_exc()
            return make_response(jsonify( { 'status': 'error', 'msg': 'There is something wrong, please contact Administrator.' } ), 400)

# Global event log - tracks all changes made by admins and users
# TODO: Add a search function, add additional ways to sort this data
@app.route('/admin/history', methods=['GET', 'POST'])
@login_required
@admin_role_required
def admin_history():
    pages = Page.query.all()
    if request.method == 'POST':
        h = History()
        result = h.remove_all()
        if result:
            history = History(msg='Remove all histories', created_by=current_user.username)
            history.add()
            return make_response(jsonify( { 'status': 'ok', 'msg': 'Changed user role successfully.' } ), 200)
        else:
            return make_response(jsonify( { 'status': 'error', 'msg': 'Can not remove histories.' } ), 500)
    if request.method == 'GET':
        histories = History.query.all()
        return render_template('admin_history.html', histories=histories, pages=pages)

# Global settings
@app.route('/admin/settings', methods=['GET'])
@login_required
@admin_role_required
def admin_settings():
    pages = Page.query.all()
    if request.method == 'GET':
        settings = Setting.query.filter(Setting.name != 'maintenance')
        return render_template('admin_settings.html', settings=settings, pages=pages)

# Toggle setting
@app.route('/admin/setting/<string:setting>/toggle', methods=['POST'])
@login_required
@admin_role_required
def admin_settings_toggle(setting):
    result = Setting().toggle(setting)
    if (result):
        return make_response(jsonify( { 'status': 'ok', 'msg': 'Toggled setting successfully.' } ), 200)
    else:
        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to toggle setting.' } ), 500)

# Change setting string
@app.route('/admin/setting/<string:setting>/edit', methods=['POST'])
@login_required
@admin_role_required
def admin_settings_edit(setting):
    pdata = request.data
    jdata = json.loads(pdata)
    new_value = jdata['value']
    result = Setting().set(setting, new_value)
    if (result):
        return make_response(jsonify( { 'status': 'ok', 'msg': 'Toggled setting successfully.' } ), 200)
    else:
        return make_response(jsonify( { 'status': 'error', 'msg': 'Unable to toggle setting.' } ), 500)

# Custom theme settings
# Doesn't do anything yet
@app.route('/admin/theme_settings')
def theme_settings():
    pages = Page.query.all()
    return render_template('theme-settings.html', pages=pages)

# LANGUAGE SETTINGS ROUTES/VIEWS #
@app.route('/admin/language_settings', methods=['GET'])
@login_required
@admin_role_required
def admin_language():
    pages = Page.query.all()
    if request.method == 'GET':
        languages = Language.query.filter(Language.name != 'maintenance')
        return render_template('language-settings.html', languages=languages, pages=pages)

# Toggle language setting
@app.route('/admin/language_settings/<string:language>/toggle', methods=['POST'])
@login_required
@admin_role_required
def admin_language_toggle(language):
    result = Setting().toggle(language)
    if (result):
        return make_response(jsonify({'status': 'ok', 'msg': 'Toggled setting successfully.'}), 200)
    else:
        return make_response(jsonify({'status': 'error', 'msg': 'Unable to toggle setting.'}), 500)

# Update language string
@app.route('/admin/language_settings/<string:language>/edit', methods=['POST'])
@login_required
@admin_role_required
def admin_language_edit(language):
    pdata = request.data
    jdata = json.loads(pdata)
    new_value = jdata['value']
    result = Language().set(language, new_value)
    if (result):
        return make_response(jsonify({'status': 'ok', 'msg': 'Toggled setting successfully.'}), 200)
    else:
        return make_response(jsonify({'status': 'error', 'msg': 'Unable to toggle setting.'}), 500)

# END LANGUAGE SETTINGS ROUTES/VIEWS #

# User profile
@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    pages = Page.query.all()
    if current_user.role.name == 'Suspended':
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        return render_template('user_profile.html', pages=pages)
    if request.method == 'POST':
        # get new profile info
        firstname = request.form['firstname'] if 'firstname' in request.form else ''
        lastname = request.form['lastname'] if 'lastname' in request.form else ''
        email = request.form['email'] if 'email' in request.form else ''
        new_password = request.form['password'] if 'password' in request.form else ''
        css_skin = request.form['css_skin'] if 'css_skin' in request.form else ''
        background_pattern = request.form['background_pattern'] if 'background_pattern' in request.form else ''
        # json data
        if request.data:
            jdata = json.loads(request.data)
            data = jdata['data']
            if jdata['action'] == 'enable_otp':
                enable_otp = data['enable_otp']
                user = User(username=current_user.username)
                user.update_profile(enable_otp=enable_otp)
                return make_response(jsonify( { 'status': 'ok', 'msg': 'Change OTP Authentication successfully. Status: %s' % enable_otp } ), 200)
        # get new avatar
        save_file_name = None
        if 'file' in request.files:
            file = request.files['file']
            if file:
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1]
                if file_extension.lower() in ['jpg', 'jpeg', 'png']:
                    save_file_name = current_user.username + '.' + file_extension
                    file.save(os.path.join(app.config['UPLOAD_DIR'], 'avatar', save_file_name))

        # update user profile
        user = User(username=current_user.username, plain_text_password=new_password, firstname=firstname, lastname=lastname, email=email, avatar=save_file_name, css_skin=css_skin, background_pattern=background_pattern, reload_info=False)
        user.update_profile()
        return render_template('user_profile.html', pages=pages)

# User avatar
@app.route('/user/avatar/<string:filename>')
def user_avatar(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_DIR'], 'avatar'), filename)

# User customization
@app.route('/user/customization')
def user_customization():
    render_template('user_customization.html')

# Default route
@app.route('/', methods=['GET', 'POST'])
@login_manager.unauthorized_handler
def home():
    pages = Page.query.all()
    # these parameters will be needed in multiple paths
    LDAP_ENABLED = True if 'LDAP_TYPE' in app.config.keys() else False
    LOGIN_TITLE = app.config['LOGIN_TITLE'] if 'LOGIN_TITLE' in app.config.keys() else ''
    BASIC_ENABLED = app.config['BASIC_ENABLED']
    SIGNUP_ENABLED = app.config['SIGNUP_ENABLED']
    GITHUB_ENABLE = app.config.get('GITHUB_OAUTH_ENABLE')
    if g.user is not None and current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if 'github_token' in session:
        me = github.get('user')
        user_info = me.data
        user = User.query.filter_by(username=user_info['name']).first()
        if not user:
            # create user
            user = User(username=user_info['name'],
                        plain_text_password=gen_salt(7),
                        email=user_info['email'])
            user.create_local_user()
        session['user_id'] = user.id
        login_user(user, remember = False)
        return redirect(url_for('index'))
    if request.method == 'GET':
        return render_template('home.html',
                               github_enabled=GITHUB_ENABLE,
                               ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE,
                               basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
    # process login
    username = request.form['username']
    password = request.form['password']
    otp_token = request.form.get('otptoken')
    auth_method = request.form.get('auth_method', 'LOCAL')
    # addition fields for registration case
    firstname = request.form.get('firstname')
    lastname = request.form.get('lastname')
    email = request.form.get('email')
    rpassword = request.form.get('rpassword')
    if None in [firstname, lastname, email]:
        #login case
        remember_me = False
        if 'remember' in request.form:
            remember_me = True
        user = User(username=username, password=password, plain_text_password=password)
        try:
            auth = user.is_validate(method=auth_method)
            if auth == False:
                return render_template('home.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
        except Exception, e:
            error = e.message['desc'] if 'desc' in e.message else e
            return render_template('home.html', error=error, ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
        # check if user enabled OPT authentication
        if user.otp_secret:
            if otp_token:
                good_token = user.verify_totp(otp_token)
                if not good_token:
                    return render_template('home.html', error='Invalid credentials', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
            else:
                return render_template('home.html', error='Token required', ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
        login_user(user, remember = remember_me)
        return redirect(request.args.get('next') or url_for('index'))
    else:
        # registration case
        user = User(username=username, plain_text_password=password, firstname=firstname, lastname=lastname, email=email)
        # TODO: Move this into the JavaScript
        # validate password and password confirmation
        if password != rpassword:
            error = "Passsword and confirmation do not match"
            return render_template('register.html', error=error, pages=pages)
        try:
            result = user.create_local_user()
            if result == True:
                return render_template('home.html', username=username, password=password, ldap_enabled=LDAP_ENABLED, login_title=LOGIN_TITLE, basic_enabled=BASIC_ENABLED, signup_enabled=SIGNUP_ENABLED, pages=pages)
            else:
                return render_template('register.html', error=result, pages=pages)
        except Exception, e:
            error = e.message['desc'] if 'desc' in e.message else e
            return render_template('register.html', error=error, pages=pages)


@app.route('/qrcode')
@login_required
def qrcode():
    if not current_user:
        return redirect(url_for('index'))
    # render qrcode for FreeTOTP
    img = qrc.make(current_user.get_totp_uri(), image_factory=qrc_svg.SvgImage)
    stream = BytesIO()
    img.save(stream)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

# Dynamic DNS IP checker
@app.route('/nic/checkip.html', methods=['GET', 'POST'])
def dyndns_checkip():
    # route covers the default ddclient 'web' setting for the checkip service
    return render_template('dyndns.html', response=request.environ.get('HTTP_X_REAL_IP', request.remote_addr))

# Dynamic DNS updater
@app.route('/nic/update', methods=['GET', 'POST'])
@dyndns_login_required
def dyndns_update():
    # dyndns protocol response codes in use are:
    # good: update successful
    # nochg: IP address already set to update address
    # nohost: hostname does not exist for this user account
    # 911: server error
    # have to use 200 HTTP return codes because ddclient does not read the return string if the code is other than 200
    # reference: https://help.dyn.com/remote-access-api/perform-update/
    # reference: https://help.dyn.com/remote-access-api/return-codes/
    hostname = request.args.get('hostname')
    myip = request.args.get('myip')
    try:
        # get all domains owned by the current user
        domains = User(id=current_user.id).get_domain()
    except:
        return render_template('dyndns.html', response='911'), 200
    domain = None
    domain_segments = hostname.split('.')
    for index in range(len(domain_segments)):
        domain_segments.pop(0)
        full_domain = '.'.join(domain_segments)
        potential_domain = Domain.query.filter(Domain.name == full_domain).first()
        if potential_domain in domains:
            domain = potential_domain
            break
    if not domain:
        history = History(msg="DynDNS update: attempted update of %s but it does not exist for this user" % hostname, created_by=current_user.username)
        history.add()
        return render_template('dyndns.html', response='nohost'), 200
    r = Record()
    r.name = hostname
    # check if the user requested record exists within this domain
    if r.exists(domain.name) and r.is_allowed:
        if r.data == myip:
            # record content did not change, return 'nochg'
            history = History(msg="DynDNS update: attempted update of %s but record did not change" % hostname, created_by=current_user.username)
            history.add()
            return render_template('dyndns.html', response='nochg'), 200
        else:
            oldip = r.data
            result = r.update(domain.name, myip)
            if result['status'] == 'ok':
                history = History(msg='DynDNS update: updated record %s in zone %s, it changed from %s to %s' % (hostname,domain.name,oldip,myip), detail=str(result), created_by=current_user.username)
                history.add()
                return render_template('dyndns.html', response='good'), 200
            else:
                return render_template('dyndns.html', response='911'), 200
    elif r.is_allowed:
        ondemand_creation = DomainSetting.query.filter(DomainSetting.domain == domain).filter(DomainSetting.setting == 'create_via_dyndns').first()
        if (ondemand_creation != None) and (strtobool(ondemand_creation.value) == True):
            record = Record(name=hostname,type='A',data=myip,status=False,ttl=3600)
            result = record.add(domain.name)
            if result['status'] == 'ok':
                history = History(msg='DynDNS update: created record %s in zone %s, it now represents %s' % (hostname,domain.name,myip), detail=str(result), created_by=current_user.username)
                history.add()
                return render_template('dyndns.html', response='good'), 200
    history = History(msg="DynDNS update: attempted update of %s but it does not exist for this user" % hostname, created_by=current_user.username)
    history.add()
    return render_template('dyndns.html', response='nohost'), 200

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    pages = Page.query.all()
    return redirect(url_for('dashboard'))
# END VIEWS
