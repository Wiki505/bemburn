import mysql.connector

mysql_connector = mysql.connector.connect(user='noroot', host='192.168.88.27', password='compass', database='BEMBURN')

def bemburn_visitor_metadata(address, username, session_status, headers, path):
    cur = mysql_connector.cursor()
    cur.execute('INSERT INTO BEMBURN_VISITOR_METADATA(ADDRESS, USERNAME, SESSION_STATUS, HEADERS, PATH) VALUES ("%s","%s", "%s", "%s", "%s")' % (address, username,session_status, headers, path))
    mysql_connector.commit()
    cur.close()
