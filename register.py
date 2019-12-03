#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from MySQL import MySQL_engine
import hashlib
import uuid

class register_engine_class():

    def user_validation(self, user):
        # FALSE, IF SPACE IN USER
        if ' ' in user:
            return '¡Character <ESPACIO> Inválido! (U)'
        elif len(user) < 4:
            return '¡Nombre de Usuario muy Corto! (4 Min)'
        elif len(user) > 13:
            return '¡Nombre de Usuario muy Largo! (12 Max)'
        else:
            # TRUE, VALID USERNAME
            return True


    def password_validation(self, password):
        # FALSE, IF SPACE IN PASSWORD
        if ' ' in password:
            return '¡Character <ESPACIO> Inválido! (U)'
        # FALSE, PASSWORD INVALID
        elif len(password) < 6:
            return '¡Contraseña muy Corta! (6 Min)'
        elif len(password) > 32:
            return '¡Contraseña muy Larga! (33 Max)'
        else:
            return True


    def user_email_verification(self, username, email):
        data = MySQL_engine().read_database("SELECT USERNAME, EMAIL FROM BEMBURN_USERS WHERE USERNAME='%s' OR EMAIL='%s'" % (username, email))
        try:
            # FALSE, THE USER CAN'T BE REGISTERED
            if data[0][0] == username:
                return 'Usuario "%s" ya está Registrado!' % username
            elif data[0][1] == email:
                return 'Correo Electrónico ya está Registrado!'
        except IndexError:
            # TRUE, THE USER CAN BE REGISTERED
            return True


def bemburn_register_engine(username, email, password, register_address, headers):
    if register_engine_class().user_validation(username) == True:
        if register_engine_class().user_email_verification(username, email) == True:
            if register_engine_class().password_validation(password) == True:
                id_string = uuid.uuid4()
                hash_password = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
                MySQL_engine().write_database("INSERT INTO BEMBURN_USERS (USERNAME, EMAIL, PASSWORD, REGISTER_ADDRESS, HEADERS, USER_ID, STATUS) "
                        "VALUES ('%s','%s','%s','%s','%s','%s','%s')" % (username, email, hash_password, register_address, headers, id_string, 0))
                return True, id_string
            else:
                alert = register_engine_class().password_validation(password)
                return alert
        else:
            alert = register_engine_class().user_email_verification(username, email)
            return alert
    else:
        alert = register_engine_class().user_validation(username)
        return alert
