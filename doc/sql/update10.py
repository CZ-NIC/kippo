import sqlite3

p = 'log/backlogs.sqlite'
dbh = sqlite3.connect(p)
cursor = dbh.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS backlogfiles (
        id INTEGER PRIMARY KEY,
        shasum TEXT NOT NULL,
        url TEXT NOT NULL,
        timestamp INTEGER NOT NULL
    );""")

cursor.execute("""
    CREATE UNIQUE INDEX backlog_shasum ON backlogfiles(shasum)
    ;""")
