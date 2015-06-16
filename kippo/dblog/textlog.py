#
# this module uses the dblog feature to create a "traditional" looking logfile
# ..so not exactly a dblog.
#

from kippo.core import dblog
import time

class DBLogger(dblog.DBLogger):
    def start(self, cfg):
        self.outfile = file(cfg.get('database_textlog', 'logfile'), 'a')

    def write(self, session, msg):
        self.outfile.write('%s [%s]: %s\r\n' % \
            (session, time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        self.outfile.flush()

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        return format(peerIP) + " " + format(peerPort)

    def handleFileDownload(self, session, args):
        self.write(session, 'File download: [%s] -> %s' % \
            (args['url'], args['outfile']))

    def handleShaSum(self, session, args):
        self.write(session, 'File SHA sum: %s [%s] -> %s' % \
            (args['shasum'], args['url'], args['outfile']))

    def handleUpdatedFile(self, session, args):
        self.write(session, 'Updated wget outfile %s to %s' % \
            (args['outfile'], args['dl_file']))

    def handleVirustotalLog(self, session, args):
        self.write(session, 'Virustotal report of %s at %s' % \
            (args['shasum'], args['permalink']))

# vim: set sw=4 et:
