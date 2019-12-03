#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import mysql.connector
import ipcalc
from MySQL import MySQL_engine
import operator

# dbConnect = mysql.connector.connect(user='noroot', host='localhost', password='compass', database='BEMBURN')

def ip_validator(IPv4):
    try:
        if ipcalc.IP(IPv4):
            return True
        else:
            return False
    except ValueError:
        return False

def check_account_validation(username):
    db = MySQL_engine().read_database("SELECT USERNAME, STATUS FROM BEMBURN_USERS WHERE USERNAME='%s'" % username)
    try:
        if db[0][1]:
            return True
        else:
            return False
    except IndexError:
        return False


def port_param(port):
    db = MySQL_engine().read_database("SELECT COUNT(ADDRESS) FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' UNION "    #  TOTAL SPECIFIC PORT
                                      "SELECT COUNT(ADDRESS) FROM VULNS_GENERAL_DATA WHERE PORT='%s'"  % (port, port)) #  TOTAL CVE ON SPECIFIC PORT
    total_port = db[0][0]            #  0
    total_cve_port = db[1][0]        #  1
    
    db = MySQL_engine().read_database("SELECT ADDRESS, COUNT(CVE) AS TOTAL FROM VULNS_GENERAL_DATA WHERE PORT='%s' GROUP BY ADDRESS ORDER BY TOTAL DESC" % (port,))
    total_vulnerable_ports = len(db) #  2

    db = MySQL_engine().read_database("SELECT ORG, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' GROUP BY ORG ORDER BY TOTAL DESC" % port)
    total_org = len(db)              #  3

    db = MySQL_engine().read_database("SELECT PRODUCT, COUNT(ADDRESS) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' GROUP BY PRODUCT ORDER BY TOTAL DESC" % port)
    total_product = len(db)          #  4

    db = MySQL_engine().read_database("SELECT OPERATIVE, COUNT(ADDRESS) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' GROUP BY OPERATIVE ORDER BY TOTAL DESC" % port)
    total_os = len(db)               #  5

    db = MySQL_engine().read_database("SELECT REGIONNAME, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' AND COUNTRYCODE='NI' GROUP BY REGIONNAME ORDER BY TOTAL DESC" % port)
    total_city = len(db)              #  6

    # TOTAL VULNERABLE PORTS GEOLOCATION
    db = MySQL_engine().read_database("SELECT REGION, COUNT(PORT) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' GROUP BY REGION ORDER BY TOTAL DESC" % port)

    regions_map = {"NI-AN": 0, "NI-AS": 0, "NI-BO": 0, "NI-CA": 0, "NI-CI": 0, "NI-CO": 0, "NI-ES": 0, "NI-GR": 0, "NI-JI": 0,
               "NI-LE": 0, "NI-MD": 0, "NI-MN": 0, "NI-MS": 0, "NI-MT": 0, "NI-NS": 0, "NI-RI": 0, "NI-SJ": 0}           #  7
    for data in db:
        if "NI-"+data[0] in regions_map:
            regions_map["NI-"+data[0]]=data[1]
        else:
            pass

    #  TOTAL VULNERABILITIES PER YEAR GRAPH
    db = MySQL_engine().read_database("SELECT CVE, COUNT(ID) AS TOTAL_CVE FROM VULNS_GENERAL_DATA WHERE PORT='%s' GROUP BY CVE ORDER BY TOTAL_CVE ASC " % port)
    CVE = {}
    for cve in db:
        if cve[0][4:8] not in CVE:
            CVE[cve[0][4:8]]=1
        else:
            CVE[cve[0][4:8]]=CVE[cve[0][4:8]]+1
    cve_per_years = sorted(CVE.items(), key=operator.itemgetter(0)) #  8

    db = MySQL_engine().read_database("SELECT ADDRESS, OPERATIVE, PRODUCT, STATE FROM SERVICE_GENERAL_METADATA WHERE PORT='%s' LIMIT 10" % port)
    top_service_data = db       #  9

    data = (
        total_port,             #  0
        total_cve_port,         #  1
        total_vulnerable_ports, #  2
        total_org,              #  3
        total_product,          #  4
        total_os,               #  5
        total_city,             #  6
        regions_map,            #  7
        cve_per_years,          #  8
        top_service_data,       #  9
    )
    return data

# port_param('80')
def host_param(host_address):
    try:
        # HOST GENERAL DATA
        db = MySQL_engine().read_database("SELECT ADDRESS, OPERATIVE, HOSTNAME, TOTAL_PORTS, TOTAL_CVE FROM HOST_GENERAL_DATA WHERE ADDRESS='%s'" % host_address)
        address = db[0][0]      #  0
        operative=db[0][1]      #  1
        hostname=db[0][2]       #  2
        open_ports=db[0][3]     #  3
        total_cve_host=db[0][4] #  4

        db = MySQL_engine().read_database("SELECT COUNTRY, REGIONNAME, CITY, LAT, LON, ISP, ORG, AS_ FROM GEODATA WHERE ADDRESS='%s'" % host_address)
        country = db[0][0] # 5
        region_name = db[0][1] # 6
        city = db[0][2] # 7
        lat = db[0][3] # 8
        lon = db[0][4] # 9
        org = db[0][6] # 10
        asn = db[0][7] # 11

        # TOTAL VULNERABILITIES PER YEAR BAR GRAPH
        db = MySQL_engine().read_database("SELECT CVE, COUNT(ID) AS TOTAL_CVE FROM VULNS_GENERAL_DATA WHERE ADDRESS='%s' GROUP BY CVE ORDER BY TOTAL_CVE ASC " % host_address)
        CVE = {}
        for cve in db:
            if cve[0][4:8] not in CVE:
                CVE[cve[0][4:8]]=1
            else:
                CVE[cve[0][4:8]]=CVE[cve[0][4:8]]+1
        cve_per_years = sorted(CVE.items(), key=operator.itemgetter(0)) # 12

        # SERVICE INFORMATION
        db = MySQL_engine().read_database("SELECT PORT, STATE, NAME, PRODUCT FROM SERVICE_GENERAL_METADATA WHERE ADDRESS='%s' LIMIT 42" % host_address)
        service_metadata = db # 13
        total_ports = len(service_metadata) # 14

        # TOTAL CVE ON DATABASE
        db = MySQL_engine().read_database("SELECT COUNT(CVE) FROM VULNS_GENERAL_DATA WHERE ADDRESS='%s'" % host_address)
        total_cve_db=db[0][0] # 15

        db = MySQL_engine().read_database("SELECT PORT, CVE FROM VULNS_GENERAL_DATA WHERE ADDRESS='%s'" % host_address)
        print(db)

        data = (
            address,          # 0
            operative,        # 1
            hostname,         # 2
            open_ports,       # 3
            total_cve_host,   # 4
            country,          # 5
            region_name,      # 6
            city,             # 7
            lat,              # 8
            lon,              # 9
            org,              # 10
            asn,              # 11
            cve_per_years,    # 12
            service_metadata, # 13
            total_ports,      # 14
            total_cve_db,     # 15
        )
        return data
    except IndexError as err:
        return False
# host_param('191.98.231.43')

def product_param(product):
    db = MySQL_engine().read_database("SELECT COUNT(PRODUCT) FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE'%s'" % ('%' + product + '%',))
    total_product = db[0][0]  #  0

    db = MySQL_engine().read_database("SELECT PRODUCT, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s' GROUP BY PRODUCT ORDER BY TOTAL DESC" % ('%' + product + '%',))
    total_product_type = len(db)   #  1

    db = MySQL_engine().read_database("SELECT PORT, COUNT(PRODUCT) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s' GROUP BY PORT ORDER BY TOTAL DESC " % ('%' + product + '%',))
    total_port_product = len(db)   #  2

    db = MySQL_engine().read_database("SELECT ORG, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s' GROUP BY ORG ORDER BY TOTAL DESC" % ('%' + product + '%',))
    total_org = len(db)      #  3

    db = MySQL_engine().read_database("SELECT PRODUCT, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE'%s' GROUP BY PRODUCT ORDER BY TOTAL DESC" % ('%' + product + '%',))
    total_os = len(db)       #  4

    db = MySQL_engine().read_database("SELECT REGIONNAME, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCt LIKE '%s' AND COUNTRYCODE='NI' GROUP BY REGIONNAME ORDER BY TOTAL DESC" % ('%' + product + '%',))
    total_departamentos = len(db)       #  5

    # """ TOP TOTAL PRODUCT SEARCH (0) """
    db = MySQL_engine().read_database("SELECT ADDRESS, PORT, NAME, PRODUCT FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s' ORDER BY ID ASC LIMIT 10" % ('%' + product + '%',))
    top_total_product = db        #  6

    # TOTAL VULNERABLE PORTS GEOLOCATION
    db = MySQL_engine().read_database("SELECT REGION, COUNT(ID) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s' GROUP BY REGION ORDER BY TOTAL DESC" % ('%' + product + '%',))

    regions_map = {"NI-AN": 0, "NI-AS": 0, "NI-BO": 0, "NI-CA": 0, "NI-CI": 0, "NI-CO": 0, "NI-ES": 0, "NI-GR": 0, "NI-JI": 0,
               "NI-LE": 0, "NI-MD": 0, "NI-MN": 0, "NI-MS": 0, "NI-MT": 0, "NI-NS": 0, "NI-RI": 0, "NI-SJ": 0}           #  7
    for data in db:
        if "NI-"+data[0] in regions_map:
            regions_map["NI-"+data[0]]=data[1]
        else:
            pass

    db = MySQL_engine().read_database("SELECT CVE FROM VULNS_GENERAL_DATA WHERE PRODUCT LIKE '%s' " % ('%' + product + '%',))
    CVE = {}
    for cve in db:
        if cve[0][4:8] not in CVE:
            CVE[cve[0][4:8]] = 1
        else:
            CVE[cve[0][4:8]] = CVE[cve[0][4:8]] + 1
    cve_per_years = sorted(CVE.items(), key=operator.itemgetter(0))  # 8


    # """ TOP TOTAL PORT ACTIVE WITH PRODUCT SEARCH (0) """
    # db = MySQL_engine().read_database("SELECT PORT, COUNT(ADDRESS) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE PRODUCT LIKE '%s'GROUP BY PORT ORDER BY TOTAL DESC LIMIT 10 " % product)

    data = (
        total_product, #  0
        total_product_type,   #  1
        total_port_product,   #  2
        total_org,     #  3
        total_os,      #  4
        total_departamentos,   #  5
        top_total_product,     #  6
        regions_map,           #  7
        cve_per_years          #  8

    )

    return data




def operative_param(operative):

    # TOTAL OPERATIVE TOTAL OPERATIVE CVE
    cur = dbConnect.cursor()
    cur.execute("SELECT COUNT(OPERATIVE) FROM HOST_GENERAL_DATA WHERE OPERATIVE LIKE '%s' UNION "
                "SELECT COUNT(OPERATIVE) FROM VULNS_GENERAL_DATA WHERE OPERATIVE LIKE '%s' " % ('%'+operative+'%','%'+operative+'%',))
    db = cur.fetchall()
    cur.close()

    total_operative = db[0][0] # 0
 #######################################################################
    try:
        total_operative_cve = db[1][0] # 1
    except IndexError:
        total_operative_cve = 0
    # TOTAL OPERATIVE TYPE
    cur = dbConnect.cursor()
    cur.execute("SELECT OPERATIVE, COUNT(ID) AS TOTAL FROM HOST_GENERAL_DATA WHERE OPERATIVE LIKE '%s' GROUP BY OPERATIVE ORDER BY TOTAL DESC " % ('%'+operative+'%',))
    db = cur.fetchall()
    cur.close()

    total_operative_type = len(db) # 2

    # TOP OPERATIVE TYPE
    cur = dbConnect.cursor()
    cur.execute("SELECT OPERATIVE, COUNT(ID) AS TOTAL FROM HOST_GENERAL_DATA WHERE OPERATIVE LIKE '%s' GROUP BY OPERATIVE ORDER BY TOTAL DESC LIMIT 10" % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()

    top_operative_type = db # 3

    # TOTAL PORT OPERATIVE
    cur = dbConnect.cursor()
    cur.execute("SELECT PORT, COUNT(OPERATIVE) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE OPERATIVE LIKE '%s' GROUP BY PORT ORDER BY TOTAL DESC" % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()

    total_operative_port=len(db) # 4

    # TOP PORT OPERATIVE
    cur = dbConnect.cursor()
    cur.execute("SELECT PORT, COUNT(OPERATIVE) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE OPERATIVE LIKE '%s' GROUP BY PORT ORDER BY TOTAL DESC LIMIT 10" % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()

    top_port_operative=db # 5

    # TOTAL VULNERABLE OPERATIVE
    cur = dbConnect.cursor()
    cur.execute("SELECT ADDRESS FROM VULNS_GENERAL_DATA WHERE OPERATIVE LIKE '%s' GROUP BY ADDRESS" % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()
    vulnerable_operative = len(db) # 6
##########################################################
    try:
        vulnerable_percent=round((vulnerable_operative/total_operative)*100) # 7
    except ZeroDivisionError:
        vulnerable_percent = 0


    # TOP CVE BAR GRAPH
    cur = dbConnect.cursor()
    cur.execute("SELECT CVE, COUNT(OPERATIVE) AS TOTAL FROM VULNS_GENERAL_DATA WHERE OPERATIVE LIKE '%s' GROUP BY CVE ORDER BY TOTAL DESC LIMIT 10 " % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()
    CVE = {} # 8
    for cve in db:
        if cve[0][4:8] not in CVE:
            CVE[cve[0][4:8]]=1
        else:
            CVE[cve[0][4:8]]=CVE[cve[0][4:8]]+1

    # TOP PORT STATE
    cur = dbConnect.cursor()
    cur.execute("SELECT STATE, COUNT(OPERATIVE) AS TOTAL FROM SERVICE_GENERAL_METADATA WHERE OPERATIVE LIKE '%s' GROUP BY STATE ORDER BY `TOTAL` DESC " % ('%' + operative + '%',))
    db = cur.fetchall()
    cur.close()

    top_port_state=db  # 9

    data=(total_operative,
          total_operative_cve,
          total_operative_type,
          top_operative_type,
          total_operative_port,
          top_port_operative,
          vulnerable_operative,
          vulnerable_percent,
          CVE,
          top_port_state
          )

    return data











""" GLOBAL GENERAL INFO """

def bemburn():

    # TOTAL ACTIVE HOST, TOTAL CVE, TOTAL OPEN PORTS (0)
    cur = dbConnect.cursor()
    cur.execute("SELECT COUNT(ID) FROM HOST_GENERAL_DATA UNION " # TOTAL HOST IN DATABASE
                "SELECT COUNT(PORT) FROM SERVICE_GENERAL_METADATA WHERE PORT !='' UNION " # TOTAL PORTS ON DATABASE
                "SELECT COUNT(PORT) FROM SERVICE_GENERAL_METADATA WHERE PORT ='' UNION " # TOTAL HOST WITH NO PORTS ON DATABASE
                "SELECT SUM(TOTAL_CVE) FROM HOST_GENERAL_DATA") # TOTAL VULNERABILITIES ON DATABASE
    db = cur.fetchall()
    cur.close()
    total_host = db[0][0] # 0
    total_ports = db[1][0] # 1
    total_no_ports = db[2][0] # 2
    total_vulns = db[3][0] # 3

    # LEN VULNERABLE PORTS
    cur = dbConnect.cursor()
    cur.execute("SELECT PORT, COUNT(ADDRESS) AS TOTAL FROM VULNS_GENERAL_DATA GROUP BY PORT ORDER BY `TOTAL` DESC ")
    db = cur.fetchall()
    cur.close()
    total_vulnerable_ports = len(db) # 4


    # TOP CVE ON DATABASE
    cur = dbConnect.cursor()
    cur.execute("SELECT CVE, COUNT(PORT) AS TOTAL FROM VULNS_GENERAL_DATA GROUP BY CVE ORDER BY TOTAL DESC LIMIT 9")
    db = cur.fetchall()
    cur.close()
    top_cve = db # 5


    # MOST USED PORTS
    cur = dbConnect.cursor()
    cur.execute("SELECT PORT, COUNT(CVE) AS TOTAL FROM VULNS_GENERAL_DATA GROUP BY PORT ORDER BY TOTAL DESC LIMIT 9")
    db = cur.fetchall()
    cur.close()
    top_vulnerable_ports = db # 6
#

    # MOST USED OPERATIVE SYSTEM
    cur = dbConnect.cursor()
    cur.execute("SELECT OPERATIVE, COUNT(ID) AS TOTAL FROM HOST_GENERAL_DATA GROUP BY OPERATIVE ORDER BY TOTAL DESC LIMIT 10")
    db = cur.fetchall()
    cur.close()
    top_operative = db # 7

#
    """ TOP 10 PRODUCTS (4) """
    cur = dbConnect.cursor()
    cur.execute("SELECT ADDRESS, HOSTNAME, OPERATIVE, TOTAL_CVE FROM HOST_GENERAL_DATA WHERE TOTAL_CVE > 0 ORDER BY TOTAL_CVE DESC LIMIT 10")
    db = cur.fetchall()
    cur.close()
    top_product = db # 8
#
#     """ TOTAL VULNERABLE AND NO VULNERABLE HOST (5) """
#     cur = dbConnect.cursor()
#     cur.execute("SELECT COUNT(TOTAL_CVE) FROM HOST_GENERAL_DATA WHERE TOTAL_CVE >'0' UNION SELECT COUNT(TOTAL_CVE) FROM HOST_GENERAL_DATA WHERE TOTAL_CVE ='0' ")
#     db_data = cur.fetchall()
#     cur.close()
#     data.append(db_data)
#
#     # """ TOP INTERNET PROVIDER (6)"""
#     # cur = dbConnect.cursor()
#     # cur.execute("SELECT ASN, INET_PROVIDER, COUNT(ID) AS TOTAL FROM HOST_GENERAL_DATA GROUP BY ASN, INET_PROVIDER ORDER BY TOTAL DESC LIMIT 10")
#     # db_data = cur.fetchall()
#     # cur.close()
#     # data.append(db_data)
#
#     """ TOP NAME (7)"""
#     cur = dbConnect.cursor()
#     cur.execute("SELECT NAME, COUNT(PORT) AS TOTAL FROM SERVICE_GENERAL_METADATA GROUP BY NAME ORDER BY TOTAL DESC LIMIT 10 ")
#     db_data = cur.fetchall()
#     cur.close()
#     data.append(db_data)
#
#
    data=(total_host,
          total_ports,
          total_no_ports,
          total_vulns,
          total_vulnerable_ports,
          top_cve,
          top_vulnerable_ports,
          top_operative,
          top_product)
    return data

# def name_param(name):
#     cur = dbConnect.cursor()
#     cur.execute("SELECT * FROM SERVICE_GENERAL_METADATA WHERE NAME LIKE '%{}%' ORDER BY ID ASC LIMIT 20".format(name))
#     data = cur.fetchall()
#     cur.close()
#     return data


#  FOR REGISTER ANY REQUESTS TO BEMBUNR SERVER, WRITE METADATA ON DATABASE
def requests_data(path, address, headers, username):
    MySQL_engine().write_database("INSERT INTO BEMBURN_REQUESTS_DATA(ADDRESS, USERNAME, HEADERS, PATH) VALUES ('%s','%s','%s','%s')" % (address, username, headers, path))

