import sqlite3
import virustotal
from kippo.core.config import config
import datetime
from time import strftime

def insert(shasum, url):
    p = config().get('honeypot', 'log_path') + '/backlogs.sqlite'
    dbh = sqlite3.connect(p)
    cursor = dbh.cursor()
    dt = datetime.datetime.now()
    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO backlogfiles (shasum, url, timestamp)
        VALUES (?,?,?) """, (shasum, url, timestamp))
    dbh.commit()
    cursor.close()

def check():
    p = config().get('honeypot', 'log_path') + '/backlogs.sqlite'
    dbh = sqlite3.connect(p)
    cursor = dbh.cursor()
    r = cursor.execute("""
        SELECT shasum, url, timestamp FROM backlogfiles""")

    for record in r:
        shasum = format(record[0])
        url = format(record[1])

        result = virustotal.get_report(shasum, None, url, None, 'db')
        if result == 1:
            print "Virustotal backlog record " + shasum + " will be deleted"
            cursor.execute("""
                DELETE FROM backlogfiles WHERE shasum = ?""", (shasum,) )
            virustotal.make_comment(shasum)
    dbh.commit()
    cursor.close()
