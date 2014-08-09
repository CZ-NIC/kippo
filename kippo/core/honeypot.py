# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os, random, pickle, time, shlex, struct, copy
from zope.interface import implements

import twisted
from twisted.cred import checkers, credentials, error
from twisted.conch import recvline
from twisted.conch.ssh import factory, session, transport
from twisted.conch.insults import insults
from twisted.internet import defer

import ttylog, fs
from userdb import UserDB
from config import config
import kippo.commands

class HoneyPotCommand(object):
    def __init__(self, honeypot, *args):
        self.honeypot = honeypot
        self.args = args
        self.writeln = self.honeypot.writeln
        self.write = self.honeypot.terminal.write
        self.nextLine = self.honeypot.terminal.nextLine
        self.fs = self.honeypot.fs

    def start(self):
        self.call()
        self.exit()

    def call(self):
        self.honeypot.writeln('Hello World! [%s]' % repr(self.args))

    def exit(self):
        self.honeypot.cmdstack.pop()
        self.honeypot.cmdstack[-1].resume()

    def ctrl_c(self):
        print 'Received CTRL-C, exiting..'
        self.writeln('^C')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT: %s' % line

    def resume(self):
        pass

    def handle_TAB(self):
        pass

class HoneyPotShell(object):
    def __init__(self, honeypot, interactive = True):
        self.honeypot = honeypot
        self.interactive = interactive
        self.showPrompt()
        self.cmdpending = []
        self.envvars = {
            'PATH':     '/bin:/usr/bin:/sbin:/usr/sbin',
            }

    def lineReceived(self, line):
        print 'CMD: %s' % line
        for i in [x.strip() for x in line.strip().split(';')]:
            if not len(i):
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
            else:
                self.showPrompt()

        if not len(self.cmdpending):
            self.showPrompt()
            return
        line = self.cmdpending.pop(0)
        try:
            cmdAndArgs = shlex.split(line)
        except:
            self.honeypot.writeln(
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
                matches = self.honeypot.fs.resolve_path_wc(arg, self.honeypot.cwd)
            except Exception as e:
                print "arg= " + arg
                print "self.honeypot.cwd= " + self.honeypot.cwd
                print str(e)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.honeypot.getCommand(cmd, envvars['PATH'].split(':'))
        if cmdclass:
            print 'Command found: %s' % (line,)
            self.honeypot.logDispatch('Command found: %s' % (line,))
            self.honeypot.call_command(cmdclass, *rargs)
        else:
            self.honeypot.logDispatch('Command not found: %s' % (line,))
            print 'Command not found: %s' % (line,)
            if len(line):
                self.honeypot.writeln('bash: %s: command not found' % cmd)
                runOrPrompt()

    def resume(self):
        if self.interactive:
            self.honeypot.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        if (self.honeypot.execcmd != None):
            return

        # Example: nas3:~#
        #prompt = '%s:%%(path)s' % self.honeypot.hostname
        # Example: root@nas3:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.honeypot.user.username, self.honeypot.hostname,)
        # Example: [root@nas3 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.honeypot.user.username, self.honeypot.hostname,)
        if not self.honeypot.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        path = self.honeypot.cwd
        homelen = len(self.honeypot.user.home)
        if path == self.honeypot.user.home:
            path = '~'
        elif len(path) > (homelen+1) and \
                path[:(homelen+1)] == self.honeypot.user.home + '/':
            path = '~' + path[homelen:]
        # Uncomment the three lines below for a 'better' CenOS look.
        # Rather than '[root@nas3 /var/log]#' is shows '[root@nas3 log]#'.
        #path = path.rsplit('/', 1)[-1]
        #if not path:
        #    path = '/'

        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

    def ctrl_c(self):
        self.honeypot.lineBuffer = []
        self.honeypot.lineBufferIndex = 0
        self.honeypot.terminal.nextLine()
        self.showPrompt()

    # Tab completion
    def handle_TAB(self):
        if not len(self.honeypot.lineBuffer):
            return
        l = ''.join(self.honeypot.lineBuffer)
        if l[-1] == ' ':
            clue = ''
        else:
            clue = ''.join(self.honeypot.lineBuffer).split()[-1]
        try:
            basedir = os.path.dirname(clue)
        except:
            pass
        if len(basedir) and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not len(basedir):
            tmppath = self.honeypot.cwd
        try:
            r = self.honeypot.fs.resolve_path(tmppath, self.honeypot.cwd)
        except:
            return
        for x in self.honeypot.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if len(files) == 0:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.honeypot.lineBufferIndex):
            self.honeypot.terminal.cursorBackward()
            self.honeypot.terminal.deleteCharacter()

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
            if newbuf == ''.join(self.honeypot.lineBuffer):
                self.honeypot.terminal.nextLine()
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.honeypot.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.honeypot.terminal.nextLine()
                    self.honeypot.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.honeypot.terminal.nextLine()
                self.showPrompt()

        self.honeypot.lineBuffer = list(newbuf)
        self.honeypot.lineBufferIndex = len(self.honeypot.lineBuffer)
        self.honeypot.terminal.write(newbuf)

class HoneyPotBaseProtocol(insults.TerminalProtocol):
    def __init__(self, user, env, execcmd = None):
        self.user = user
        self.env = env
        self.execcmd = execcmd
        self.hostname = self.env.cfg.get('honeypot', 'hostname')
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.env.fs))
        if self.fs.exists(user.home):
            self.cwd = user.home
        else:
            self.cwd = '/'
        # commands is also a copy so we can add stuff on the fly
        self.commands = copy.copy(self.env.commands)
        self.password_input = False
        self.cmdstack = []

    def logDispatch(self, msg):
        transport = self.terminal.transport.session.conn.transport
        transport.factory.logDispatch(transport.transport.sessionno, msg)

    def connectionMade(self):
        self.displayMOTD()

        transport = self.terminal.transport.session.conn.transport

        #transport = self.transport.transport.session.conn.transport
        self.realClientIP = transport.getPeer().address.host
        self.clientVersion = transport.otherVersionString
        self.logintime = transport.logintime
        self.ttylog_file = transport.ttylog_file

        # source IP of client in user visible reports (can be fake or real)
        cfg = config()
        if cfg.has_option('honeypot', 'fake_addr'):
            self.clientIP = cfg.get('honeypot', 'fake_addr')
        else:
            self.clientIP = self.realClientIP

    def displayMOTD(self):
        try:
            self.writeln(self.fs.file_contents('/etc/motd'))
        except:
            pass

    # this doesn't seem to be called upon disconnect, so please use 
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        pass
        # not sure why i need to do this:
        # scratch that, these don't seem to be necessary anymore:
        #del self.fs
        #del self.commands

    def txtcmd(self, txt):
        class command_txtcmd(HoneyPotCommand):
            def call(self):
                print 'Reading txtcmd from "%s"' % txt
                f = file(txt, 'r')
                self.write(f.read())
                f.close()
        return command_txtcmd

    def getCommand(self, cmd, paths):
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in ('.', '/'):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in ['%s/%s' % (self.fs.resolve_path(x, self.cwd), cmd) \
                    for x in paths]:
                if self.fs.exists(i):
                    path = i
                    break
        txt = os.path.abspath('%s/%s' % \
            (self.env.cfg.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)
        if path in self.commands:
            return self.commands[path]
        return None

    def lineReceived(self, line):
        # don't execute additional commands after execcmd 
        if self.execcmd != None:
            return
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def writeln(self, data):
        self.terminal.write(data)
        self.terminal.nextLine()

    def call_command(self, cmd, *args):
        obj = cmd(self, *args)
        self.cmdstack.append(obj)
        obj.start()

    def addInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.append(interactor)

    def delInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.remove(interactor)

    def uptime(self, reset = None):
        transport = self.terminal.transport.session.conn.transport
        r = time.time() - transport.factory.starttime
        if reset:
            transport.factory.starttime = reset
        return r

class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):

    def __init__(self, user, env, execcmd = None):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, user, env, execcmd)

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [HoneyPotShell(self)]

        transport = self.terminal.transport.session.conn.transport
        transport.factory.sessions[transport.transport.sessionno] = self

        if self.execcmd != None:
            print 'Running exec cmd "%s"' % self.execcmd
            self.cmdstack[0].lineReceived(self.execcmd)
            self.terminal.transport.session.conn.sendRequest(
                self.terminal.transport.session,
                'exit-status',
                struct.pack('>L', 0))
            self.terminal.transport.session.conn.sendClose(
                self.terminal.transport.session)
            return

        self.keyHandlers.update({
            '\x04':     self.handle_CTRL_D,
            '\x15':     self.handle_CTRL_U,
            '\x03':     self.handle_CTRL_C,
            '\x09':     self.handle_TAB,
            })

    # this doesn't seem to be called upon disconnect, so please use
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def call_command(self, cmd, *args):
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, cmd, *args)

    def keystrokeReceived(self, keyID, modifier):
        transport = self.terminal.transport.session.conn.transport
#        if type(keyID) == type(''):
#            ttylog.ttylog_write(transport.ttylog_file, len(keyID),
#                ttylog.TYPE_INPUT, time.time(), keyID)
        recvline.HistoricRecvLine.keystrokeReceived(self, keyID, modifier)

    # Easier way to implement password input?
    def characterReceived(self, ch, moreCharactersComing):
        if self.mode == 'insert':
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex:self.lineBufferIndex+1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input: 
            self.terminal.write(ch)

    def handle_RETURN(self):
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self):
        self.cmdstack[-1].ctrl_c()

    def handle_CTRL_U(self):
        for i in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
        self.lineBufferIndex = 0

    def handle_CTRL_D(self):
        self.call_command(self.commands['exit'])

    def handle_TAB(self):
        self.cmdstack[-1].handle_TAB()

class HoneyPotExecProtocol(HoneyPotBaseProtocol):

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)

        self.cmdstack = [HoneyPotShell(self, interactive=False)]

        print 'Running exec command "%s"' % self.execcmd
        self.cmdstack[0].lineReceived(self.execcmd)
        self.terminal.transport.session.conn.sendRequest(
            self.terminal.transport.session,
            'exit-status',
            struct.pack('>L', 0))
        self.terminal.transport.session.conn.sendClose(
            self.terminal.transport.session)

class LoggingServerProtocol(insults.ServerProtocol):
    def connectionMade(self):
        transport = self.transport.session.conn.transport

        transport.ttylog_file = '%s/tty/%s-%s.log' % \
            (config().get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'),
            int(random.random() * 10000))
        print 'Opening TTY log: %s' % transport.ttylog_file
        ttylog.ttylog_open(transport.ttylog_file, time.time())

        transport.ttylog_open = True

        insults.ServerProtocol.connectionMade(self)

    def write(self, bytes, noLog = False):
        transport = self.transport.session.conn.transport
        for i in transport.interactors:
            i.sessionWrite(bytes)
        if transport.ttylog_open and not noLog:
            ttylog.ttylog_write(transport.ttylog_file, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)
        insults.ServerProtocol.write(self, bytes)

    def dataReceived(self, data, noLog = False):
        transport = self.transport.session.conn.transport
        if transport.ttylog_open and not noLog:
            ttylog.ttylog_write(transport.ttylog_file, len(data),
                ttylog.TYPE_INPUT, time.time(), data)
        insults.ServerProtocol.dataReceived(self, data)

    # this doesn't seem to be called upon disconnect, so please use 
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        insults.ServerProtocol.connectionLost(self, reason)

class HoneyPotEnvironment(object):
    def __init__(self):
        self.cfg = config()
        self.commands = {}
        import kippo.commands
        for c in kippo.commands.__all__:
            module = __import__('kippo.commands.%s' % c,
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)
        self.fs = pickle.load(file(
            self.cfg.get('honeypot', 'filesystem_file'), 'rb'))

class HoneypotPasswordChecker:
    implements(checkers.ICredentialsChecker)

    credentialInterfaces = (credentials.IUsernamePassword,
        credentials.IPluggableAuthenticationModules)

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(error.UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                credentials.pamConversion)
        return defer.fail(error.UnhandledCredentials())

    def checkPamUser(self, username, pamConversion):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username)

    def cbCheckPamUser(self, responses, username):
        for response, zero in responses:
            if self.checkUserPass(username, response):
                return defer.succeed(username)
        return defer.fail(error.UnauthorizedLogin())

    def checkUserPass(self, username, password):
        if UserDB().checklogin(username, password):
            print 'login attempt [%s/%s] succeeded' % (username, password)
            return True
        else:
            print 'login attempt [%s/%s] failed' % (username, password)
            return False

# vim: set sw=4 et:
