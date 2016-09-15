# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import shlex
import re
import copy
import pickle
from twisted.python import log

from cowrie.core import fs
from cowrie.core.config import config

class HoneyPotCommand(object):
    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = args
        self.env = self.protocol.cmdstack[0].envvars
        self.writeln = self.protocol.writeln
        self.write = self.protocol.terminal.write
        self.nextLine = self.protocol.terminal.nextLine
        self.fs = self.protocol.fs

    def start(self):
        self.call()
        self.exit()

    def call(self):
        self.protocol.writeln('Hello World! [%s]' % (repr(self.args),))

    def exit(self):
        self.protocol.cmdstack.pop()
        self.protocol.cmdstack[-1].resume()

    def handle_CTRL_C(self):
        log.msg('Received CTRL-C, exiting..')
        self.writeln('^C')
        self.exit()

    def lineReceived(self, line):
        log.msg('INPUT: %s' % (line,))

    def resume(self):
        pass

    def handle_TAB(self):
        pass

    def handle_CTRL_D(self):
        pass

class HoneyPotShell(object):
    def __init__(self, protocol, interactive = True):
        self.protocol = protocol
        self.interactive = interactive
        self.showPrompt()
        self.cmdpending = []
        self.envvars = {
            'PATH':     '/bin:/usr/bin:/sbin:/usr/sbin',
            }

    def lineReceived(self, line):
        log.msg('CMD: %s' % (line,))
        comment = re.compile('^\s*#')
        for i in [x.strip() for x in re.split(';|&&|\n', line.strip())[:10]]:
            if not len(i):
                continue
            if comment.match(i):
                continue
            self.cmdpending.append(i)
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()

    def runCommand(self):
        def runOrPrompt():
            if len(self.cmdpending):
                self.runCommand()
            elif self.interactive:
                self.showPrompt()
            else:
                self.protocol.terminal.transport.session.sendEOF()
                self.protocol.terminal.transport.session.sendClose()

        if not len(self.cmdpending):
            if self.interactive:
                self.showPrompt()
            else:
                self.protocol.terminal.transport.session.sendEOF()
                self.protocol.terminal.transport.session.sendClose()
            return

        line = self.cmdpending.pop(0)
        try:
            line = line.replace('>', ' > ').replace('|', ' | ').replace('<',' < ')
            cmdAndArgs = shlex.split(line)
        except:
            self.protocol.writeln(
                'bash: syntax error: unexpected end of file')
            # could run runCommand here, but i'll just clear the list instead
            self.cmdpending = []
            self.showPrompt()
            return

        # probably no reason to be this comprehensive for just PATH...
        envvars = copy.copy(self.envvars)
        cmd = None
        while len(cmdAndArgs):
            piece = cmdAndArgs.pop(0)
            if piece.count('='):
                key, value = piece.split('=', 1)
                envvars[key] = value
                continue
            cmd = piece
            break
        args = cmdAndArgs

        if not cmd:
            runOrPrompt()
            return

        rargs = []
        matches = ""
        for arg in args:
            try:
                matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
            except Exception as e:
                print "arg= " + arg
                print "self.protocol.cwd= " + self.protocol.cwd
                print str(e)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.protocol.getCommand(cmd, envvars['PATH'].split(':'))
        if cmdclass:
            print 'Command found: %s' % (line,)
            self.protocol.logDispatch('Command found: %s' % (line,))
            self.protocol.call_command(cmdclass, *rargs)
        else:
            self.protocol.logDispatch('Command not found: %s' % (line,))
            print 'Command not found: %s' % (line,)
            if len(line):
                self.protocol.writeln('bash: %s: command not found' % (cmd,))
                runOrPrompt()

    def resume(self):
        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        if not self.interactive:
            return

        # Example: nas3:~#
        #prompt = '%s:%%(path)s' % self.protocol.hostname
        # Example: root@nas3:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.protocol.user.username, self.protocol.hostname,)
        # Example: [root@nas3 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.protocol.user.username, self.protocol.hostname,)
        if not self.protocol.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        path = self.protocol.cwd
        homelen = len(self.protocol.user.home)
        if path == self.protocol.user.home:
            path = '~'
        elif len(path) > (homelen+1) and \
                path[:(homelen+1)] == self.protocol.user.home + '/':
            path = '~' + path[homelen:]
        # Uncomment the three lines below for a 'better' CentOS look.
        # Rather than '[root@nas3 /var/log]#' is shows '[root@nas3 log]#'.
        #path = path.rsplit('/', 1)[-1]
        #if not path:
        #    path = '/'

        attrs = {'path': path}
        self.protocol.terminal.write(prompt % attrs)

    def handle_CTRL_C(self):
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.nextLine()
        self.showPrompt()

    def handle_CTRL_D(self):
        log.msg('Received CTRL-D, exiting..')
        self.protocol.call_command(self.protocol.commands['exit'])

    # Tab completion
    def handle_TAB(self):
        if not len(self.protocol.lineBuffer):
            return
        l = ''.join(self.protocol.lineBuffer)
        if l[-1] == ' ':
            clue = ''
        else:
            clue = ''.join(self.protocol.lineBuffer).split()[-1]
        try:
            basedir = os.path.dirname(clue)
        except:
            pass
        if len(basedir) and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not len(basedir):
            tmppath = self.protocol.cwd
        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except:
            return
        for x in self.protocol.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if len(files) == 0:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ''
        if len(files) == 1:
            newbuf = ' '.join(l.split()[:-1] + \
                ['%s%s' % (basedir, files[0][fs.A_NAME])])
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += '/'
            else:
                newbuf += ' '
        else:
            if len(os.path.basename(clue)):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ''
            first = l.split(' ')[:-1]
            newbuf = ' '.join(first + ['%s%s' % (basedir, prefix)])
            if newbuf == ''.join(self.protocol.lineBuffer):
                self.protocol.terminal.nextLine()
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.nextLine()
                    self.protocol.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.protocol.terminal.nextLine()
                self.showPrompt()

        self.protocol.lineBuffer = list(newbuf)
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbuf)

class HoneyPotEnvironment(object):
    """
    """
    def __init__(self, cfg):
        self.cfg = cfg

        self.commands = {}
        self.hostname = self.cfg.get('honeypot', 'hostname')

        import cowrie.commands
        for c in cowrie.commands.__all__:
            module = __import__('cowrie.commands.%s' % (c,),
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)

        self.fs = pickle.load(file(self.cfg.get('honeypot', 'filesystem_file'), 'rb'))

# vim: set sw=4 et:
