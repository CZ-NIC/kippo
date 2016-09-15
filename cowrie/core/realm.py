# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from zope.interface import implements

import twisted
from twisted.conch import interfaces as conchinterfaces
from twisted.python import log

from cowrie.core import protocol
from cowrie.core import server
from cowrie.core import ssh
from config import config

class HoneyPotRealm:
    implements(twisted.cred.portal.IRealm)

    def __init__(self):
        self.cfg = config()
        self.servers = {}

    def requestAvatar(self, avatarId, mind, *interfaces):
        if mind in self.servers:
            log.msg( "Using existing server for mind %s" % mind )
            _server = self.servers[mind]
        else:
            log.msg( "Starting new server for mind %s" % mind )
            _server = server.CowrieServer(self.cfg)
            self.servers[mind] = _server

        if conchinterfaces.IConchUser in interfaces:
            return interfaces[0], \
                ssh.HoneyPotAvatar(avatarId, _server), lambda: None
        else:
            raise Exception, "No supported interfaces found."

