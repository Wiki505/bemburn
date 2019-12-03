#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
from MySQL import MySQL_engine

class login_engine_class():

    def user_validation(self, user):
        # FALSE, IF SPACE IN USER
        if ' ' in user:
            return 'Space character invalid! (U)'
        elif len(user) < 4:
            return 'User too short! (4 Min)'
        elif len(user) > 13:
            return 'User too long! (12 Max)'
        else:
            # TRUE, VALID USERNAME
            return True

    def password_validation(self, password):
        # FALSE, IF SPACE IN PASSWORD
        if ' ' in password:
            return 'Space character invalid! (P)'
        # FALSE, PASSWORD INVALID
        elif len(password) < 6:
            return 'Password too short! (6 Min)'
        elif len(password) > 32:
            return 'Password too long! (33 Max)'
        else:
            return True

    def user_password_validation(self, username, password):
        hash_password = hashlib.sha3_256(password.encode('utf-8')).hexdigest()
        data = MySQL_engine().read_database("SELECT USERNAME FROM BEMBURN_USERS WHERE USERNAME='%s'" % (username))
        try:
            if data[0][0] == username:
                data = MySQL_engine().read_database("SELECT PASSWORD FROM BEMBURN_USERS WHERE USERNAME='%s'" % (username))
                if data[0][0] == hash_password:
                    return True
                else:
                    return 'Incorrect Password!'
        except IndexError:
            return 'Invalid User! "%s"' % username

def bemburn_login_engine(username, password):
    if login_engine_class().user_validation(username) == True:
        if login_engine_class().password_validation(password) == True:
            if login_engine_class().user_password_validation(username, password) == True:
                return True
            else:
                alert = login_engine_class().user_password_validation(username, password)
                return alert
        else:
            alert = login_engine_class().password_validation(password)
            return alert
    else:
        alert = login_engine_class().user_validation(username)
        return alert
