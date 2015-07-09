# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import copy
import time
import uuid
import struct

from zope.interface import implementer

import twisted
from twisted.cred import portal
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.conch.ssh import factory, userauth, keys, session, transport, filetransfer, forwarding
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
import twisted.conch.ls
from twisted.python import log, components
from twisted.conch.openssh_compat import primes
from twisted.conch.ssh.common import NS, getNS

import ConfigParser

from cowrie.core import ttylog, fs, honeypot, sshserver, connection
import cowrie.core.protocol
from config import config
from cowrie.core.auth import UserDB
from cowrie.core import auth
from twisted.internet import defer

import hashlib, shutil
from cowrie.core import virustotal
from cowrie.core import virustotal_backlogs

class HoneyPotSSHUserAuthServer(userauth.SSHUserAuthServer):
    def serviceStarted(self):
        userauth.SSHUserAuthServer.serviceStarted(self)
        self.bannerSent = False

    def sendBanner(self):
        if self.bannerSent:
            return
        cfg = config()
        self.bannerSent = True
        try:
            honeyfs = cfg.get('honeypot', 'contents_path')
            issuefile = honeyfs + "/etc/issue.net"
            data = file( issuefile ).read()
        except IOError:
            return
        if not data or not len(data.strip()):
            return
        self.transport.sendPacket(
            userauth.MSG_USERAUTH_BANNER, NS(data) + NS('en'))

    def ssh_USERAUTH_REQUEST(self, packet):
        self.sendBanner()
        return userauth.SSHUserAuthServer.ssh_USERAUTH_REQUEST(self, packet)

    # Overridden to pass src_ip to auth.UsernamePasswordIP
    def auth_password(self, packet):
        password = getNS(packet[1:])[0]
        src_ip = self.transport.transport.getPeer().host
        c = auth.UsernamePasswordIP(self.user, password, src_ip)
        return self.portal.login(c, None, conchinterfaces.IConchUser).addErrback(
                                                        self._ebPassword)

    # Overridden to pass src_ip to auth.PluggableAuthenticationModulesIP
    def auth_keyboard_interactive(self, packet):
        if self._pamDeferred is not None:
            self.transport.sendDisconnect(
                    transport.DISCONNECT_PROTOCOL_ERROR,
                    "only one keyboard interactive attempt at a time")
            return defer.fail(error.IgnoreAuthentication())
        src_ip = self.transport.transport.getPeer().host
        c = auth.PluggableAuthenticationModulesIP(self.user, self._pamConv, src_ip)
        return self.portal.login(c, None, conchinterfaces.IConchUser)

# As implemented by Kojoney
class HoneyPotSSHFactory(factory.SSHFactory):
    services = {
        'ssh-userauth': HoneyPotSSHUserAuthServer,
        'ssh-connection': cowrie.core.connection.CowrieSSHConnection,
        }

    # Special delivery to the loggers to avoid scope problems
    def logDispatch(self, sessionid, msg):
        for dblog in self.dbloggers:
            dblog.logDispatch(sessionid, msg)
        for output in self.output_plugins:
            output.logDispatch(sessionid, msg)

    def __init__(self):
        cfg = config()

        # protocol^Wwhatever instances are kept here for the interact feature
        self.sessions = {}

        # for use by the uptime command
        self.starttime = time.time()

        # load/create keys
        rsa_pubKeyString, rsa_privKeyString = getRSAKeys()
        dsa_pubKeyString, dsa_privKeyString = getDSAKeys()
        self.publicKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_pubKeyString),
          'ssh-dss': keys.Key.fromString(data=dsa_pubKeyString)}
        self.privateKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_privKeyString),
          'ssh-dss': keys.Key.fromString(data=dsa_privKeyString)}

        # load db loggers
        self.dbloggers = []
        for x in cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            dbengine = 'database_' + engine
            lcfg = ConfigParser.SafeConfigParser()
            lcfg.add_section(dbengine)
            for i in cfg.options(x):
                lcfg.set(dbengine, i, cfg.get(x, i))
            lcfg.add_section('honeypot')
            for i in cfg.options('honeypot'):
                lcfg.set('honeypot', i, cfg.get('honeypot', i))
            print 'Loading dblog engine: %s' % (engine,)
            dblogger = __import__(
                'cowrie.dblog.%s' % (engine,),
                globals(), locals(), ['dblog']).DBLogger(lcfg)
            log.startLoggingWithObserver(dblogger.emit, setStdout=False)
            self.dbloggers.append(dblogger)

        # load output modules
        self.output_plugins = [];
        for x in cfg.sections():
            if not x.startswith('output_'):
                continue
            engine = x.split('_')[1]
            output = 'output_' + engine
            lcfg = ConfigParser.SafeConfigParser()
            lcfg.add_section(output)
            for i in cfg.options(x):
                lcfg.set(output, i, cfg.get(x, i))
            lcfg.add_section('honeypot')
            for i in cfg.options('honeypot'):
                lcfg.set('honeypot', i, cfg.get('honeypot', i))
            log.msg('Loading output engine: %s' % (engine,))
            output = __import__(
                'cowrie.output.%s' % (engine,),
                globals(), locals(), ['output']).Output(lcfg)
            log.startLoggingWithObserver(output.emit, setStdout=False)
            self.output_plugins.append(output)

    def buildProtocol(self, addr):
        """
        Create an instance of the server side of the SSH protocol.

        @type addr: L{twisted.internet.interfaces.IAddress} provider
        @param addr: The address at which the server will listen.

        @rtype: L{twisted.conch.ssh.SSHServerTransport}
        @return: The built transport.
        """

        _modulis = '/etc/ssh/moduli', '/private/etc/moduli'
        cfg = config()

        t = HoneyPotTransport()
        if cfg.has_option('honeypot', 'ssh_version_string'):
            t.ourVersionString = cfg.get('honeypot','ssh_version_string')
        else:
            t.ourVersionString = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"

        t.supportedPublicKeys = self.privateKeys.keys()

        for _moduli in _modulis:
            try:
                self.primes = primes.parseModuliFile(_moduli)
                break
            except IOError as err:
                pass

        if not self.primes:
            log.msg("Moduli not found, disabling diffie-hellman-group-exchange-sha1")
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske

        t.factory = self
        return t

@implementer(portal.IRealm)
class HoneyPotRealm:

    def __init__(self):
        # I don't know if i'm supposed to keep static stuff here
        self.env = honeypot.HoneyPotEnvironment()

    def requestAvatar(self, avatarId, mind, *interfaces):
        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                HoneyPotAvatar(avatarId, self.env), lambda: None
        else:
            raise Exception, "No supported interfaces found."

class HoneyPotTransport(cowrie.core.sshserver.CowrieSSHServerTransport):
    """
    @ivar logintime: time of login

    @ivar interactors: interactors

    @ivar ttylog_open: whether log is open

    @ivar transportId: UUID of this transport

    @ivar _hadVersion: used so we only send key exchange after receive version info
    """

    _hadVersion = False
    ttylog_open = False
    interactors = []
    transportId = ''

    def connectionMade(self):
        self.transportId = uuid.uuid4().hex
        self.interactors = []

        log.msg( 'New connection: %s:%s (%s:%s) [session: %d]' % \
            (self.transport.getPeer().host, self.transport.getPeer().port,
            self.transport.getHost().host, self.transport.getHost().port,
            self.transport.sessionno) )

        cowrie.core.sshserver.CowrieSSHServerTransport.connectionMade(self)

    def sendKexInit(self):
        # Don't send key exchange prematurely
        if not self.gotVersion:
            return
        cowrie.core.sshserver.CowrieSSHServerTransport.sendKexInit(self)

    def dataReceived(self, data):
        cowrie.core.sshserver.CowrieSSHServerTransport.dataReceived(self, data)
        # later versions seem to call sendKexInit again on their own
        if twisted.version.major < 11 and \
                not self._hadVersion and self.gotVersion:
            self.sendKexInit()
            self._hadVersion = True

    def ssh_KEXINIT(self, packet):
        print 'Remote SSH version: %s' % (self.otherVersionString,)
        return cowrie.core.sshserver.CowrieSSHServerTransport.ssh_KEXINIT(self, packet)

    # this seems to be the only reliable place of catching lost connection
    def connectionLost(self, reason):
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        if self.ttylog_open:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False
        cowrie.core.sshserver.CowrieSSHServerTransport.connectionLost(self, reason)

class HoneyPotSSHSession(session.SSHSession):

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        self.__dict__['request_auth_agent_req@openssh.com'] = self.request_agent

    def request_env(self, data):
        name, rest = getNS(data)
        value, rest = getNS(rest)
        if rest:
            raise ValueError("Bad data given in env request")
        log.msg('request_env: %s=%s' % (name, value) )
        return 0

    def request_agent(self, data):
        log.msg('request_agent: %s' % repr(data) )
        return 0

    def request_x11_req(self, data):
        log.msg('request_x11: %s' % repr(data) )
        return 0

    # this is reliably called on session close/disconnect and calls the avatar
    def closed(self):
        session.SSHSession.closed(self)

    # utility function to request to send EOF for this session
    def sendEOF(self):
        self.conn.sendEOF(self)

    def eofReceived(self):
        log.msg('got eof')
        self.sendClose()

    # utility function to request to send close for this session
    def sendClose(self):
        self.conn.sendClose(self)

    def loseConnection(self):
        self.conn.sendRequest(self, 'exit-status', "\x00"*4)
        session.SSHSession.loseConnection(self)

    def channelClosed(self):
        log.msg( "Called channelClosed in SSHSession")

# FIXME: recent twisted conch avatar.py uses IConchuser here
@implementer(conchinterfaces.ISession)
class HoneyPotAvatar(avatar.ConchUser):

    def __init__(self, username, env):
        avatar.ConchUser.__init__(self)
        self.username = username
        self.env = env
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.env.fs))
        self.hostname = self.env.hostname
        self.protocol = None

        self.channelLookup.update({'session': HoneyPotSSHSession})
        self.windowSize = [80,24]
        self.channelLookup['direct-tcpip'] = CowrieOpenConnectForwardingClient

        # sftp support enabled only when option is explicitly set
        if self.env.cfg.has_option('honeypot', 'sftp_enabled'):
            if ( self.env.cfg.get('honeypot', 'sftp_enabled') == "true" ):
                self.subsystemLookup['sftp'] = filetransfer.FileTransferServer

        self.uid = self.gid = UserDB().getUID(self.username)
        if not self.uid:
            self.home = '/root'
        else:
            self.home = '/home/' + username

    def openShell(self, protocol):
        serverProtocol = cowrie.core.protocol.LoggingServerProtocol(
            cowrie.core.protocol.HoneyPotInteractiveProtocol, self, self.env)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def getPty(self, terminal, windowSize, attrs):
        print 'Terminal size: %s %s' % windowSize[0:2]
        self.windowSize = windowSize
        return None

    def execCommand(self, protocol, cmd):
        cfg = config()
        # default is enabled
        if cfg.has_option('honeypot', 'exec_enabled'):
            if ( cfg.get('honeypot', 'exec_enabled') != "true" ):
                print 'exec disabled not executing command: "%s"' % cmd
                raise os.OSError

        print 'Executing command'
        serverProtocol = cowrie.core.protocol.LoggingServerProtocol(
            cowrie.core.protocol.HoneyPotExecProtocol, self, self.env, cmd)
        serverProtocol.makeConnection(protocol)
        protocol.makeConnection(session.wrapProtocol(serverProtocol))

    def closed(self):
        pass

    def eofReceived(self):
        pass

    def windowChanged(self, windowSize):
        self.windowSize = windowSize

def getRSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'rsa_public_key')
    private_key = cfg.get('honeypot', 'rsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new RSA keypair..."
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = twisted.conch.ssh.keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = twisted.conch.ssh.keys.Key(rsaKey).toString('openssh')
        file(public_key, 'w+b').write(publicKeyString)
        file(private_key, 'w+b').write(privateKeyString)
        print "done."
    else:
        publicKeyString = file(public_key).read()
        privateKeyString = file(private_key).read()
    return publicKeyString, privateKeyString

def getDSAKeys():
    cfg = config()
    public_key = cfg.get('honeypot', 'dsa_public_key')
    private_key = cfg.get('honeypot', 'dsa_private_key')
    if not (os.path.exists(public_key) and os.path.exists(private_key)):
        print "Generating new DSA keypair..."
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = twisted.conch.ssh.keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = twisted.conch.ssh.keys.Key(dsaKey).toString('openssh')
        file(public_key, 'w+b').write(publicKeyString)
        file(private_key, 'w+b').write(privateKeyString)
    else:
        publicKeyString = file(public_key).read()
        privateKeyString = file(private_key).read()
    return publicKeyString, privateKeyString

@implementer(conchinterfaces.ISFTPFile)
class CowrieSFTPFile:

    def __init__(self, server, filename, flags, attrs):
        self.server = server
        self.filename = filename
        self.transfer_completed = 0
        self.bytes_written = 0
        openFlags = 0
        if flags & FXF_READ == FXF_READ and flags & FXF_WRITE == 0:
            openFlags = os.O_RDONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == 0:
            openFlags = os.O_WRONLY
        if flags & FXF_WRITE == FXF_WRITE and flags & FXF_READ == FXF_READ:
            openFlags = os.O_RDWR
        if flags & FXF_APPEND == FXF_APPEND:
            openFlags |= os.O_APPEND
        if flags & FXF_CREAT == FXF_CREAT:
            openFlags |= os.O_CREAT
        if flags & FXF_TRUNC == FXF_TRUNC:
            openFlags |= os.O_TRUNC
        if flags & FXF_EXCL == FXF_EXCL:
            openFlags |= os.O_EXCL
        if attrs.has_key("permissions"):
            mode = attrs["permissions"]
            del attrs["permissions"]
        else:
            mode = 0777
        self.fd, self.realfile = server.fs.open(filename, openFlags, mode)
        if attrs:
            self.server.setAttrs(filename, attrs)

        # cache a copy of file in memory to read from in readChunk
        if flags & FXF_READ == FXF_READ:
            self.contents = self.server.fs.file_contents(self.filename)

    def close(self):
        cfg = config()

        if ( self.bytes_written > 0 ):
            self.server.fs.update_size(self.filename, self.bytes_written) 

        if self.realfile is not None:
            try:
                shasum = hashlib.sha256(open(self.realfile, 'rb').read()).hexdigest()
            except Exception as e:
                print format(e)
                return self.server.fs.close(self.fd)

            msg = 'SHA sum %s of file %s' % (shasum, self.realfile)
            print msg

            hash_path = '%s/%s' % (cfg.get('honeypot', 'download_path'), shasum)

            if not os.path.exists(hash_path):
                print "moving " + self.realfile + " -> " + hash_path
                shutil.move(self.realfile, hash_path)

                if cfg.has_option('virustotal', 'apikey'):
                    virustotal.get_report(shasum, self.filename, 'SFTP')
            else:
                print "deleting " + self.realfile + " with sha sum " + shasum
                os.remove(self.realfile)
            f = self.server.fs.getfile(self.filename)
            f[9] = hash_path

        if cfg.has_option('virustotal', 'apikey'):
            print "now checking Virustotal backlogs ssh"
            virustotal_backlogs.check()

        return self.server.fs.close(self.fd)

    def readChunk(self, offset, length):
        return self.contents[offset:offset+length]

    def writeChunk(self, offset, data):
        self.server.fs.lseek(self.fd, offset, os.SEEK_SET)
        self.server.fs.write(self.fd, data)
        self.bytes_written += len(data)

    def getAttrs(self):
        s = self.server.fs.stat(self.filename)
        return self.server._getAttrs(s)

    def setAttrs(self, attrs):
        raise NotImplementedError

class CowrieSFTPDirectory:

    def __init__(self, server, directory):
        self.server = server
        self.files = server.fs.listdir(directory)
        self.dir = directory

    def __iter__(self):
        return self

    def next(self):
        try:
            f = self.files.pop(0)
        except IndexError:
            raise StopIteration
        else:
            s = self.server.fs.lstat(os.path.join(self.dir, f))
            longname = twisted.conch.ls.lsLine(f, s)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)

    def close(self):
        self.files = []

@implementer(conchinterfaces.ISFTPServer)
class CowrieSFTPServer:

    def __init__(self, avatar):
        self.avatar = avatar
        self.fs = self.avatar.fs

    def _absPath(self, path):
        home = self.avatar.home
        return os.path.abspath(os.path.join(home, path))

    def _setAttrs(self, path, attrs):
        if attrs.has_key("uid") and attrs.has_key("gid"):
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if attrs.has_key("permissions"):
            self.fs.chmod(path, attrs["permissions"])
        if attrs.has_key("atime") and attrs.has_key("mtime"):
            self.fs.utime(path, attrs["atime"], attrs["mtime"])

    def _getAttrs(self, s):
        return {
            "size": s.st_size,
            "uid": s.st_uid,
            "gid": s.st_gid,
            "permissions": s.st_mode,
            "atime": int(s.st_atime),
            "mtime": int(s.st_mtime)
        }

    def gotVersion(self, otherVersion, extData):
        return {}

    def openFile(self, filename, flags, attrs):
        print "SFTP openFile: %s" % filename
        return CowrieSFTPFile(self, self._absPath(filename), flags, attrs)

    def removeFile(self, filename):
        print "SFTP removeFile: %s" % filename
        return self.fs.remove(self._absPath(filename))

    def renameFile(self, oldpath, newpath):
        print "SFTP renameFile: %s %s" % (oldpath, newpath) 
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    def makeDirectory(self, path, attrs):
        print "SFTP makeDirectory: %s" % path
        path = self._absPath(path)
        self.fs.mkdir2(path)
        self._setAttrs(path, attrs)
        return 

    def removeDirectory(self, path):
        print "SFTP removeDirectory: %s" % path
        return self.fs.rmdir(self._absPath(path))

    def openDirectory(self, path):
        print "SFTP OpenDirectory: %s" % path
        return CowrieSFTPDirectory(self, self._absPath(path))

    def getAttrs(self, path, followLinks):
        print "SFTP getAttrs: %s" % path
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat(path)
        else:
            s = self.fs.lstat(path)
        return self._getAttrs(s)

    def setAttrs(self, path, attrs):
        print "SFTP setAttrs: %s" % path
        path = self._absPath(path)
        return self._setAttrs(path, attrs)

    def readLink(self, path):
        print "SFTP readLink: %s" % path
        path = self._absPath(path)
        return self.fs.readlink(path)

    def makeLink(self, linkPath, targetPath):
        print "SFTP makeLink: %s" % path
        linkPath = self._absPath(linkPath)
        targetPath = self._absPath(targetPath)
        return self.fs.symlink(targetPath, linkPath)

    def realPath(self, path):
        print "SFTP realPath: %s" % path
        return self.fs.realpath(self._absPath(path))

    def extendedRequest(self, extName, extData):
        raise NotImplementedError

components.registerAdapter( CowrieSFTPServer, HoneyPotAvatar, conchinterfaces.ISFTPServer)

def CowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg( "direct-tcp connection attempt to %s:%i" % remoteHP )
    return CowrieConnectForwardingChannel(remoteHP,
       remoteWindow=remoteWindow,
       remoteMaxPacket=remoteMaxPacket,
       avatar=avatar)

class CowrieConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):

    def channelOpen(self, specificData):
        log.msg( "Faking channel open %s:%i" % self.hostport )

    def dataReceived(self, data):
        log.msg( "received data %s" % repr( data ))


# vim: set sw=4 et:
