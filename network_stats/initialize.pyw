import sqlite3

conn = sqlite3.connect('communications.db')
# TODO : voir detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
# pour recuperer date_com au format date
c = conn.cursor()

# Create table
# TODO: modifier additional_data (preciser)
c.execute('''CREATE TABLE IF NOT EXISTS communication 
    (id_com integer PRIMARY KEY, date_com timestamp, protocole text, ip_src text, ip_dst text, content text, additional_data text)''')

conn.commit()
conn.close()
