from cowrie.core import dblog
from twisted.python import log
import uuid
import psycopg2
from psycopg2.extras import DictCursor

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        if cfg.has_option('database_postgresql', 'port'):
            port = int(cfg.get('database_postgresql', 'port'))
        else:
            port = 5432
        self.db  = psycopg2.connect(
            database = cfg.get('database_postgresql', 'database'),
            host = cfg.get('database_postgresql', 'host'),
            user = cfg.get('database_postgresql', 'username'),
            password = cfg.get('database_postgresql', 'password'),
            port = port)
        self.cursor = self.db.cursor(cursor_factory=DictCursor)

    def simpleQuery(self, sql, args):
        try:
            self.cursor.execute(sql, args)
            self.db.commit()
        except Exception as e:
            log.msg( 'SQL Error:', str(e))

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid4().hex
        self.createSessionWhenever(sid, peerIP, int(hostPort), hostIP)
        return sid

    def createSessionWhenever(self, sid, peerIP, peerPort, hostIP):
        sensorname = self.getSensor() or hostIP
        self.cursor.execute(
            'SELECT id FROM sensors WHERE ip = %s', (sensorname,))
        row = self.cursor.fetchone()
        if row:
            id = row['id']
        else:
            self.simpleQuery(
                'INSERT INTO sensors (ip) VALUES (%s)', (sensorname,))
            self.cursor.execute(
                'SELECT id FROM sensors WHERE ip = %s', (sensorname,))
            row = self.cursor.fetchone()
            id = int(row['id'])
        # now that we have a sensorID, continue creating the session
        self.simpleQuery(
            'INSERT INTO sessions (id, starttime, sensor, ip, port)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s, %s)',
            (sid, self.nowUnix(), id, peerIP, peerPort))

    def handleConnectionLost(self, session, args):
        self.simpleQuery(
            'UPDATE sessions SET endtime = to_timestamp(%s)' + \
            ' WHERE id = %s',
            (self.nowUnix(), session))

    def handleLoginFailed(self, session, args):
        self.simpleQuery('INSERT INTO auth (session, success' + \
            ', username, password, timestamp)' + \
            ' VALUES (%s, %s, %s, %s, to_timestamp(%s))',
            (session, 0, args['username'], args['password'], self.nowUnix()))

    def handleLoginSucceeded(self, session, args):
        self.simpleQuery('INSERT INTO auth (session, success' + \
            ', username, password, timestamp)' + \
            ' VALUES (%s, %s, %s, %s, to_timestamp(%s))',
            (session, 1, args['username'], args['password'], self.nowUnix()))

    def handleCommand(self, session, args):
        self.simpleQuery('INSERT INTO input' + \
            ' (session, timestamp, success, input)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s)',
            (session, self.nowUnix(), 1, args['input']))

    def handleUnknownCommand(self, session, args):
        self.simpleQuery('INSERT INTO input' + \
            ' (session, timestamp, success, input)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s)',
            (session, self.nowUnix(), 0, args['input']))

    def handleInput(self, session, args):
        self.simpleQuery('INSERT INTO input' + \
            ' (session, timestamp, realm, input)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s)',
            (session, self.nowUnix(), args['realm'], args['input']))

    def handleTerminalSize(self, session, args):
        self.simpleQuery('UPDATE sessions SET termsize = %s' + \
            ' WHERE id = %s',
            ('%sx%s' % (args['width'], args['height']), session))

    def handleClientVersion(self, session, args):
        self.cursor.execute(
            'SELECT id FROM clients WHERE version = %s', \
            (args['version'],))
        row = self.cursor.fetchone()
        if row:
            id = int(row['id'])
        else:
            self.simpleQuery(
                'INSERT INTO clients (version) VALUES (%s)', \
                (args['version'],))
            self.cursor.execute(
                'SELECT id FROM clients WHERE version = %s', \
                (args['version'],))
            row = self.cursor.fetchone()
            id = int(row['id'])
        self.simpleQuery(
            'UPDATE sessions SET client = %s WHERE id = %s',
            (id, session))

    def handleFileDownload(self, session, args):
        self.simpleQuery('INSERT INTO downloads' + \
            ' (session, timestamp, url, outfile)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s)',
            (session, self.nowUnix(), args['url'], args['outfile']))

    def handleSFTPDownload(self, session, args):
        self.simpleQuery('INSERT INTO downloads' + \
            ' (session, timestamp, url, outfile, shasum)' + \
            ' VALUES (%s, to_timestamp(%s), %s, %s, %s)',
            (session, self.nowUnix(), 'SFTP', args['outfile'], args['shasum']))

    def handleShaSum(self, session, args):
        self.simpleQuery(
            'UPDATE downloads SET shasum = %s WHERE outfile = %s',
            (args['shasum'], args['outfile']))

# vim: set sw=4 et:
