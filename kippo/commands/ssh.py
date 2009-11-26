# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from kippo.core.honeypot import HoneyPotCommand
from twisted.internet import reactor
import time, re, md5

commands = {}

class command_ssh(HoneyPotCommand):
    def start(self):
        if not self.args:
            for l in (
                    'usage: ssh [-1246AaCfgKkMNnqsTtVvXxY] [-b bind_address] [-c cipher_spec]',
                    '           [-D [bind_address:]port] [-e escape_char] [-F configfile]',
                    '           [-i identity_file] [-L [bind_address:]port:host:hostport]',
                    '           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]',
                    '           [-R [bind_address:]port:host:hostport] [-S ctl_path]',
                    '           [-w local_tun[:remote_tun]] [user@]hostname [command]',
                    ):
                self.writeln(l)
            self.exit()
            return
        arg = self.args[0].strip()
        if arg.count('@'):
            user, host = arg.split('@', 1)
        else:
            user, host = 'root', arg

        if re.match('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', host):
            self.ip = host
        else:
            s = md5.md5(host).hexdigest()
            self.ip = '.'.join([str(int(x, 16)) for x in
                (s[0:2], s[2:4], s[4:6], s[6:8])])
        self.host = host
        self.user = user

        self.writeln('The authenticity of host \'%s (%s)\' can\'t be established.' % \
            (self.host, self.ip))
        self.writeln('RSA key fingerprint is 9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.')
        self.write('Are you sure you want to continue connecting (yes/no)? ')
        self.callbacks = [self.yesno, self.wait]

    def yesno(self, line):
        self.writeln(
            'Warning: Permanently added \'%s\' (RSA) to the list of known hosts.' % \
            self.host)
        self.write('%s@%s\'s password: ' % (self.user, self.host))
        self.honeypot.password_input = True

    def wait(self, line):
        reactor.callLater(2, self.finish, line)

    def finish(self, line):
        self.pause = False
        rest, host = self.host, 'localhost'
        rest = self.host.strip().split('.')
        if len(rest) and rest[0].isalpha():
            host = rest[0]
        self.honeypot.hostname = host
        self.honeypot.cwd = '/root'
        self.honeypot.password_input = False
        self.writeln(
            'Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686' % \
            self.honeypot.hostname)
        self.writeln('Last login: %s from 192.168.9.4' % \
            time.ctime(time.time() - 123123))
        self.exit()

    def lineReceived(self, line):
        print 'INPUT (ssh):', line
        if len(self.callbacks):
            self.callbacks.pop(0)(line)
commands['/usr/bin/ssh'] = command_ssh

# vim: set sw=4 et:
