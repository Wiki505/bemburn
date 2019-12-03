import mysql.connector

mysql_connector = mysql.connector.connect(user='noroot', host='192.168.88.27', password='compass', database='BEMBURN')

class MySQL_engine():
    
    """ This class define the MySQL process for al engine """
    
    def __init__(self):
        self.cursor = mysql_connector.cursor()

    def read_database(self, mysql_query):
        self.cursor.execute("%s" % mysql_query)
        data = self.cursor.fetchall()
        self.cursor.close()
        return data

    def write_database(self, mysql_query):
        self.cursor.execute("%s" % mysql_query)
        mysql_connector.commit()
        self.cursor.close()
