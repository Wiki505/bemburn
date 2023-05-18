from flask_mail import Mail, Message
from itsdangerous import URLSafeSerializer
from MySQL import MySQL_engine
from itsdangerous.exc import BadSignature

url_serializer = URLSafeSerializer("889782a5e0491ad44501ef37ef84ff98b5526c7a251d9075eea63c4daeaf662a") #  "compass"

def email_confirmation(server,email, id_string):
    mail_settings = {
        "MAIL_SERVER": 'smtp.gmail.com',
        "MAIL_PORT": 465,
        "MAIL_USE_SSL": True,
        "MAIL_USE_TSL": False,
        "MAIL_USERNAME": '@gmail.com',
        "MAIL_PASSWORD": ''}
    server.config.update(mail_settings)

    mail = Mail()
    mail.init_app(server)
    server_mail = Mail(server)

    url_validation = url_serializer.dumps([email,str(id_string)])

    msg = Message("Verificación de Cuenta",
                  sender=("Bemburn Machine", "bemburnmachine@gmail.com"),
                  recipients=["%s" % email],
                  body="""
                  Gracias por utilizar los servicios de Bemburn, has click en el enlace para validar tu cuenta.
                  ---> http://192.168.88.27:1080/account_validation/%s
                  
                  Para mayor información: +505 7871 4878 | +505 5846 9596 | bemburnmachine@gmail.com
                  """ % url_validation)
    server_mail.send(msg)


def email_validation(token):
    try:
        data = url_serializer.loads(token)
        email = data[0]
        user_id = data[1]
    except BadSignature as err:
        return False
    db_data = MySQL_engine().read_database("SELECT EMAIL, USER_ID FROM BEMBURN_USERS WHERE EMAIL='%s' AND USER_ID='%s'" % (email, user_id))
    if email == db_data[0][0] and user_id == db_data[0][1]:
        MySQL_engine().write_database("UPDATE BEMBURN_USERS SET STATUS='%d' WHERE EMAIL='%s' AND USER_ID='%s'" % (1,email,user_id))
        return True
    else:
        return False

