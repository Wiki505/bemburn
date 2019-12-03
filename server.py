#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, flash, redirect, render_template, request, session, url_for, send_file
import os
import engine
import json
from login import bemburn_login_engine
from register import bemburn_register_engine
import SMTP
import mysql.connector

bemburn_server = Flask(__name__)

@bemburn_server.route('/')
def index():
    try:
        # IF USERNAME ARE LOGGED IN SESSION, SERVER RETURN BEMBURN SEARCH
        if 'username' in session:
            username = session['username']
            if engine.check_account_validation(username):
                path = '/index'
                address = request.remote_addr
                headers = json.dumps(dict(request.headers))
                engine.requests_data(path, address, headers, username)
                return render_template('bemburn.html', USER=username, SESSION=True)
            else:
                session.pop('username', None)
                flash('Validar Correo Electrónico')
                return render_template('index.html', SESSION=False)

        else:
            username = None
            path = '/index'
            address = request.remote_addr
            headers = json.dumps(dict(request.headers))
            engine.requests_data(path, address, headers, username)
            return render_template('index.html', SESSION=False)
    except mysql.connector.errors.OperationalError:
        flash('Servidor Sobrecargado! intentar en 5 minutos')
        return render_template('overloaded_server.html')


@bemburn_server.route('/')
def bemburn():
    # IF USERNAME ARE LOGGED IN SESSION, SERVER RETURN BEMBURN SEARCH, USER AND REGISTER ON DATABASE
    if 'username' in session:
        username = session['username']
        if engine.check_account_validation(username):
            path = '/bemburn'
            address = request.remote_addr
            headers = json.dumps(dict(request.headers))
            engine.requests_data(path, address, headers, username)

            return render_template('bemburn.html', USER=username)
        else:
            flash('Validar Cuenta')
            return  render_template('index.html')
    # ELSE, REGISTER ON DATABASE AND REDIRECT TO INDEX FOR LOGIN
    else:
        username = None
        path = '/bemburn'
        address = request.remote_addr
        headers = json.dumps(dict(request.headers))
        engine.requests_data(path, address, headers, username)
        return redirect(url_for('index'))


@bemburn_server.route('/registro')
def registro():
    if 'username' in session:
        username = session['username']
        if engine.check_account_validation(username):
            path = '/registro'
            address = request.remote_addr
            headers = json.dumps(dict(request.headers))
            engine.requests_data(path, address, headers, username)
            return render_template('bemburn.html', USER=username)
        else:
            flash('Validar Cuenta')
            return  render_template('index.html')

    else:
        username = None
        path = '/registro'
        address = request.remote_addr
        headers = json.dumps(dict(request.headers))
        engine.requests_data(path, address, headers, username)
        return render_template('registro.html')


@bemburn_server.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        path = '/register_engine'
        address = request.remote_addr
        headers = json.dumps(dict(request.headers))
        engine.requests_data(path, address, headers, None)

        # FORM DATA
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if len(username) == 0:
            flash('¡Campo Usuario está Vacio!')
            return redirect(url_for('registro'))

        elif len(email) == 0:
            flash('¡Campo Correo está Vacio!')
            return redirect(url_for('registro'))

        elif len(password) == 0:
            flash('¡Campo Contraseña está Vacio!')
            return redirect(url_for('registro'))

        else:
            result = bemburn_register_engine(username, email, password, address, headers)
            if result[0] == True:
                SMTP.email_confirmation(bemburn_server, email, result[1])
                flash('Revisa tu Correo Electrónico')
                return redirect(url_for('index'))
            else:
                flash(result)
                return redirect(url_for('index'))

@bemburn_server.route('/account_validation/<token>')
def account_validation(token):

    data = SMTP.email_validation(token)
    print(data)
    if data:
        flash('Cuenta Activa')
        return redirect(url_for('index'))
    else:
        flash('No se validó')
        return redirect(url_for('index'))


@bemburn_server.route('/login', methods=['GET','POST'])
def login():

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(username) == 0:
            path = '/register_engine'
            address = request.remote_addr
            headers = json.dumps(dict(request.headers))
            engine.requests_data(path, address, headers, None)
            flash('¡Ups! un campo quedó vacio...')
            return redirect(url_for('index'))

        elif len(password) == 0:
            flash('¡Ups! un campo quedó vacio...')
            return redirect(url_for('index'))

        # USER AND SESSION VALIDATION
        process_result = bemburn_login_engine(username, password)

        if process_result == True:
            # flash(process_result)
            session['username'] = username
            return redirect(url_for('bemburn'))
        else:
            flash(process_result)
            return redirect(url_for('index'))


@bemburn_server.route('/logout')
def logout():
   # remove the username from the session if it is there
   session.pop('username', None)
   flash('Thanks for use bemburn! ;-)')
   return redirect(url_for('index'))


@bemburn_server.route('/search')
def search():
    try:
        # filtering = "'ª\º|@""$%&;,-_ḉ+*}][?¿)(/><"
        # param = request.args.get('query').translate({ord(i): None for i in filtering})
        param = request.args.get('query')

        #   NET PARAMETER WITH FILTER
        if param[:5] in ['host:','host=']:
            if engine.ip_validator(param[5:]):
                return redirect('/host/%s' % param[5:])
            else:
                flash('¡IPv4 no válida!')
                return redirect(url_for('bemburn'))

        #   PORT PARAMETER WITH FILTER
        elif param[:5] in ['port:','port=']:
            if param[5:].isdigit() and int(param[5:]) > 0 and int(param[5:]) < 65535:
                data = engine.port_param(param[5:])
                if 'username' in session:
                    username = session['username']
                    if engine.check_account_validation(username):
                        path = '/registro'
                        address = request.remote_addr
                        headers = json.dumps(dict(request.headers))
                        engine.requests_data(path, address, headers, username)
                        return render_template('port.html', DATA=data, PORT=param[5:], SESSION=True, USER=username)
                    else:
                        flash('Validar Cuenta')
                        return render_template('index.html', SESSION=False)
                else:
                    username = None
                    path = '/registro'
                    address = request.remote_addr
                    headers = json.dumps(dict(request.headers))
                    engine.requests_data(path, address, headers, username)
                    return render_template('port.html', DATA=data, PORT=param[5:], SESSION=False)
            else:
                if 'username' in session:
                    username = session['username']
                    if engine.check_account_validation(username):
                        path = '/registro'
                        address = request.remote_addr
                        headers = json.dumps(dict(request.headers))
                        engine.requests_data(path, address, headers, username)
                        flash('¡Puerto Inválido! :O')
                        return redirect(url_for('bemburn'))
                else:
                    username = None
                    path = '/registro'
                    address = request.remote_addr
                    headers = json.dumps(dict(request.headers))
                    engine.requests_data(path, address, headers, username)
                    flash('¡Puerto Inválido! :O')
                    return redirect(url_for('no_results'))

        # #   OS PARAMETER WITH FILTER
        # elif param[:3] in ['os:','os=']:
        #     if len(param[3:]) <= 156:
        #         data = engine.operative_param(param[3:])
        #         if data[0] == 0 and data[1] == 0 and data[2] == 0:
        #             flash('Operative System Not Found')
        #             return redirect(url_for('bemburn'))
        #         else:
        #             return render_template('os_param.html', DATA=data)
        #     else:
        #         flash('Operative System Not Found')
        #         return redirect(url_for('bemburn'))
        #
        # PRODUCT PARAMETER WITH FILTER
        elif param[:8] in ['product:','product=']:
            if len(param[8:]) <= 156:
                data = engine.product_param(param[8:])
                if 'username' in session:
                    username = session['username']
                    path = '/product'
                    address = request.remote_addr
                    headers = json.dumps(dict(request.headers))
                    engine.requests_data(path, address, headers, username)
                    return render_template('product.html', DATA=data, PRODUCT=param[8:], SESSION=True)
                else:
                    username = None
                    path = '/product'
                    address = request.remote_addr
                    headers = json.dumps(dict(request.headers))
                    engine.requests_data(path, address, headers, username)
                    return render_template('product.html', DATA=data, PRODUCT=param[8:], SESSION=False)
            else:
                flash('Product Not Found')
                return redirect(url_for('bemburn'))
        #   IF NOT A PARAMETER OR OTHER THING
        else:
            flash('Invalid Parameter, Try with "port:80" or a valid "IPv4" Address!')
            return redirect(url_for('bemburn'))

    # THIS EXCEPTION COME WITH NO RESULT ON BEMBURN ENGINE
    except IndexError as err:
        flash('¡Ups! No hay resultados :-O')
        return redirect(url_for('bemburn'))

        #
        # #   HOSTNAME PARAMETER WITH FILTER
        # elif param[:9] in ['hostname:','hostname=']:
        #     if len(param[9:]) <= 156:
        #         data = engine.product_param(param[9:])
        #         return render_template('product_param.html', DATA=data)
        #     else:
        #         flash('Hostname Not Found')
        #         return redirect(url_for('bemburn'))
        #
        # #   GLOBAL PARAMETER WITH FILTER
        # elif param[:8] in ['control:','control=']:
        #     if param[8:] == 'panel':
        #         return redirect(url_for('bemburn'))
        #     else:
        #         flash('Invalid Control Access')
        #         return redirect(url_for('bemburn'))


@bemburn_server.route('/host/<host_address>')
def host(host_address):

    address=host_address.lower().translate({ord(i): None for i in "'ª\º|@""$%&;,-_=ḉ+*}][?¿)(/><"})
    if engine.ip_validator(address):
        if engine.host_param(host_address) == False:
            flash('¡No se Encontró Resultados!')
            return redirect(url_for('bemburn'))
        else:
            pass

        if 'username' in session:
            username = session['username']
            if engine.check_account_validation(username):
                path = '/host_engine'
                address = request.remote_addr
                headers = json.dumps(dict(request.headers))
                engine.requests_data(path, address, headers, username)
                data = engine.host_param(host_address)
                return render_template('host.html', DATA=data, USER=username, HOST=host_address, SESSION=True)

        else:
            username = None
            path = '/host_engine'
            address = request.remote_addr
            headers = json.dumps(dict(request.headers))
            engine.requests_data(path, address, headers, username)
            data = engine.host_param(host_address)
            return render_template('host.html', DATA=data, HOST=host_address, SESSION=False)

    else:
        flash('¡No se Encontró Resultados!')
        return redirect(url_for('bemburn'))

@bemburn_server.errorhandler(404)
def not_found(e):
    return render_template("404.html")


@bemburn_server.route('/politicas_de_privacidad')
def politicas_de_privacidad():
    return render_template("privacy.html")


@bemburn_server.route('/bemburn_files/')
def bemburn_files():
    try:
        return send_file('/home/noroot/Documents/BEMBURN/Bemburn-Machine/shared/bemburn_doc001.pdf', attachment_filename='bemburn_doc001.pdf')
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    """ Cross-Site Request Forgery (CSRF) Protection """
    bemburn_server.secret_key = os.urandom(33)
    """ Run Server with Debug on Specific Port """
    bemburn_server.run(debug=True, host='0.0.0.0', port=1080)
