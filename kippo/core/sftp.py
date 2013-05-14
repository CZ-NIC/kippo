# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import twisted
from twisted.conch import avatar, interfaces as conchinterfaces
from twisted.conch.interfaces import ISFTPServer, ISFTPFile 
from twisted.conch.ssh import filetransfer
from twisted.conch.ssh.filetransfer import FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL
from twisted.python import failure, log, components
from zope.interface import implements
from copy import deepcopy, copy
from twisted.conch.ls import lsLine

import sys, os, random, pickle, time, stat, struct

from kippo.core import fs
from kippo.core.honeypot import HoneyPotAvatar

class KippoSFTPFile:
    implements(ISFTPFile)

    def __init__(self, server, filename, flags, attrs):
        self.server = server
	self.filename = filename
	self.transfer_completed = 0
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
        fd = server.fs.open(filename, openFlags, mode )
        if attrs:
            self.server.setAttrs(filename, attrs)
        self.fd = fd

    def close(self):
        return self.server.fs.close(self.fd)

    def readChunk(self, offset, length):
	if ( self.transfer_completed == 1 ):
            return ""
	print "readChunk: %s %s" % ( offset, length )
        # this limits us to the maximum of 1 chunk, typically 32K
	contents = self.server.fs.file_contents( self.filename )
	self.transfer_completed = 1
	return contents

    def writeChunk(self, offset, data):
	self.server.fs.lseek( self.fd, offset )
	self.server.fs.write( self.fd,data)

    def getAttrs(self):
        s = self.server.fs.fstat(self.fd)
        return self.server._getAttrs(s)

    def setAttrs(self, attrs):
        raise NotImplementedError

class KippoSFTPDirectory:

    def __init__(self, server, directory):
        self.server = server
        self.files = server.fs.listdir( directory )
        self.dir = directory

    def __iter__(self):
        return self

    def next(self):
        try:
            f = self.files.pop(0)
        except IndexError:
            raise StopIteration
        else:
            s = self.server.fs.lstat( os.path.join(self.dir, f))
            longname = lsLine(f, s)
            attrs = self.server._getAttrs(s)
            return (f, longname, attrs)

    def close(self):
        self.files = []

class KippoSFTPServer:
    implements(conchinterfaces.ISFTPServer)

    def __init__( self, avatar ):
	self.avatar = avatar
	# we shouldn't copy fs here, but at avatar instantiation
        self.fs = fs.HoneyPotFilesystem(deepcopy(self.avatar.env.fs))

    def _absPath(self, path):
        home = self.avatar.home
        return os.path.abspath(os.path.join(home, path))

    def _setAttrs(self, path, attrs):
        if attrs.has_key("uid") and attrs.has_key("gid"):
            self.fs.chown(path, attrs["uid"], attrs["gid"])
        if attrs.has_key("permissions"):
            self.fs.chmod(path, attrs["permissions"])
        if attrs.has_key("atime") and attrs.has_key("mtime"):
            self.fs.utime(path, (attrs["atime"], attrs["mtime"]))

    def _getAttrs(self, s):
        return {
            "size" : s.st_size,
            "uid" : s.st_uid,
            "gid" : s.st_gid,
            "permissions" : s.st_mode,
            "atime" : int(s.st_atime),
            "mtime" : int(s.st_mtime)
        }

    def gotVersion(self, otherVersion, extData):
        return {}

    def openFile(self, filename, flags, attrs):
	print "SFTP openFile: %s" % filename
        return KippoSFTPFile(self, self._absPath(filename), flags, attrs)

    def removeFile(self, filename):
	print "SFTP removeFile: %s" % filename
	return self.fs.remove(self._absPath(filename))

    def renameFile(self, oldpath, newpath):
	print "SFTP renameFile: %s %s" % (oldpath, newpath) 
        return self.fs.rename(self._absPath(oldpath), self._absPath(newpath))

    def makeDirectory(self, path, attrs):
	print "SFTP makeDirectory: %s" % path
        path = self._absPath(path)
        self.fs.mkdir(path)
        self._setAttrs(path, attrs)

    def removeDirectory(self, path):
	print "SFTP removeDirectory: %s" % path
	return self.fs.rmdir(self.absPath(path))

    def openDirectory(self, path):
	print "SFTP OpenDirectory: %s" % path
        return KippoSFTPDirectory(self, self._absPath(path))

    def getAttrs(self, path, followLinks):
	print "SFTP getAttrs: %s" % path
        path = self._absPath(path)
        if followLinks:
            s = self.fs.stat( path)
        else:
            s = self.fs.lstat( path)
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

# vim: set sw=4 et:
