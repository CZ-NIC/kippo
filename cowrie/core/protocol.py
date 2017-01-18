# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import random
import time

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.python import log
from copy import copy
from cowrie.core import ttylog, utils
from cowrie.core import honeypot
from cowrie.core.config import config

class HoneyPotBaseProtocol(insults.TerminalProtocol):
    def __init__(self, avatar):
        self.user = avatar
        self.env = avatar.env
        self.cfg = self.env.cfg
        self.hostname = avatar.server.hostname
        self.fs = avatar.server.fs
        if self.fs.exists(avatar.home):
            self.cwd = avatar.home
        else:
            self.cwd = '/'
        # commands is also a copy so we can add stuff on the fly
        self.commands = copy(self.env.commands)
        self.password_input = False
        self.cmdstack = []

    def logDispatch(self, msg):
        transport = self.terminal.transport.session.conn.transport
        transport.factory.logDispatch(transport.transport.sessionno, msg)

    def connectionMade(self):
        transport = self.terminal.transport.session.conn.transport

        self.realClientIP = transport.transport.getPeer().host
        self.realClientPort = transport.transport.getPeer().port
        self.clientVersion = transport.otherVersionString
        self.logintime = time.time()
        self.ttylog_file = transport.ttylog_file

        # source IP of client in user visible reports (can be fake or real)
        if self.cfg.has_option('honeypot', 'fake_addr'):
            self.clientIP = self.cfg.get('honeypot', 'fake_addr')
        else:
            self.clientIP = self.realClientIP

        if self.cfg.has_option('honeypot', 'internet_facing_ip'):
            self.kippoIP = self.cfg.get('honeypot', 'internet_facing_ip')
        else:
            # Hack to get ip
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.kippoIP = s.getsockname()[0]
                s.close()
            except:
                self.kippoIP = '192.168.0.1'

    def eofReceived(self):
        log.msg("received eof, sending ctrl-d to command")
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()

    # this is only called on explicit logout, not on disconnect
    # this indicates the closing of the channel/session, not the closing of the connection
    def connectionLost(self, reason):
        pass
        # not sure why i need to do this:
        # scratch that, these don't seem to be necessary anymore:
        #del self.fs
        #del self.commands

    def txtcmd(self, txt):
        class command_txtcmd(honeypot.HoneyPotCommand):
            def call(self):
                print 'Reading txtcmd from "%s"' % txt
                with open(txt, 'r') as f:
                    self.write(f.read())
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
        txt = os.path.normpath('%s/%s' % \
            (self.env.cfg.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)
        if path in self.commands:
            return self.commands[path]
        return None

    def lineReceived(self, line):
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def writeln(self, data):
        # sometimes still called after disconnect because of a deferred
        if self.terminal:
            self.terminal.write(data)
            self.terminal.nextLine()

    def call_command(self, cmd, *args):
        obj = cmd(self, *args)
        self.cmdstack.append(obj)
        obj.start()

    def uptime(self, reset=None):
        transport = self.terminal.transport.session.conn.transport
        r = time.time() - transport.factory.starttime
        if reset:
            transport.factory.starttime = reset
        return r

class HoneyPotExecProtocol(HoneyPotBaseProtocol):

    def __init__(self, avatar, execcmd):
        self.execcmd = execcmd
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]

        print 'Running exec command "%s"' % self.execcmd
        self.cmdstack[0].lineReceived(self.execcmd)

class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        self.displayMOTD()
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self)]

        transport = self.terminal.transport.session.conn.transport
        transport.factory.sessions[transport.transport.sessionno] = self

        self.keyHandlers.update({
            '\x01':     self.handle_HOME,	# CTRL-A
            '\x02':     self.handle_LEFT,	# CTRL-B
            '\x03':     self.handle_CTRL_C,	# CTRL-C
            '\x04':     self.handle_CTRL_D,	# CTRL-D
            '\x05':     self.handle_END,	# CTRL-E
            '\x06':     self.handle_RIGHT,	# CTRL-F
            '\x09':     self.handle_TAB,
            '\x0B':     self.handle_CTRL_K,	# CTRL-K
            '\x0E':     self.handle_DOWN,	# CTRL-N
            '\x10':     self.handle_UP,		# CTRL-P
            '\x15':     self.handle_CTRL_U,	# CTRL-U
            })

    def addInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.append(interactor)

    def delInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.remove(interactor)

    def displayMOTD(self):
        try:
            self.writeln(self.fs.file_contents('/etc/motd'))
        except:
            pass

    def lastlogExit(self):
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = utils.durationHuman(time.time() - self.logintime)
        with open( '%s/lastlog.txt' % self.cfg.get('honeypot', 'data_path'), 'a') as f:
            f.write('root\tpts/0\t%s\t%s - %s (%s)\n' % \
                (self.clientIP, starttime, endtime, duration))

    # this doesn't seem to be called upon disconnect, so please use
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        self.lastlogExit()
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def call_command(self, cmd, *args):
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, cmd, *args)

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
        self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self):
        self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self):
        self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self):
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0:self.lineBufferIndex]

    def handle_CTRL_U(self):
        for i in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
        self.lineBufferIndex = 0


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
        transport.stdinlog_file = '%s/tty/%s-%s.log' % \
            (config().get('honeypot', 'download_path'),
            time.strftime('%Y%m%d-%H%M%S'),
            int(random.random() * 10000))
        transport.stdinlog_open = True

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

        if transport.stdinlog_open and not noLog:
            f = file( transport.stdinlog_file, 'ab' )
            f.write(data)
            f.close
        insults.ServerProtocol.dataReceived(self, data)

    def eofReceived(self):
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()

    # override super to remove the terminal reset on logout
    def loseConnection(self):
        self.transport.loseConnection()

    def connectionLost(self, reason):
        insults.ServerProtocol.connectionLost(self, reason)

# vim: set sw=4 et:
