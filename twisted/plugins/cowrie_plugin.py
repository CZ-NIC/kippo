from zope.interface import implementer

import os
import sys

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet, service
from twisted.cred import portal

from cowrie.core.config import config
from cowrie import core
import cowrie.core.ssh

class Options(usage.Options):
    optParameters = [
        ["port", "p", 0, "The port number to listen on.", int],
#        ["config", "c", 'cowrie.cfg', "The configuration file to use."]
        ]

@implementer(IServiceMaker, IPlugin)
class CowrieServiceMaker(object):
    tapname = "cowrie"
    description = "She sells sea shells by the sea shore."
    options = Options

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in Cowrie.
        """

        if os.name == 'posix' and os.getuid() == 0:
            print 'ERROR: You must not run cowrie as root!'
            sys.exit(1)

        cfg = config()

        if cfg.has_option('honeypot', 'listen_addr'):
            listen_addr = cfg.get('honeypot', 'listen_addr')
        else:
            listen_addr = '0.0.0.0'
               
        # preference: 1, option, 2, config, 3, default of 2222
        if options['port'] != 0:
            listen_port = int(options["port"])
        elif cfg.has_option('honeypot', 'listen_port'):
            listen_port = int(cfg.get('honeypot', 'listen_port'))
        else:
            listen_port = 2222

        factory = core.ssh.HoneyPotSSHFactory()
        factory.portal = portal.Portal(core.ssh.HoneyPotRealm())
        factory.portal.registerChecker(core.auth.HoneypotPublicKeyChecker())
        factory.portal.registerChecker(core.auth.HoneypotPasswordChecker())

        top_service = top_service = service.MultiService()

        for i in listen_addr.split():
            svc = internet.TCPServer(listen_port, factory, interface=i)
            svc.setServiceParent(top_service)

        if cfg.has_option('honeypot', 'interact_enabled') and \
                 cfg.get('honeypot', 'interact_enabled').lower() in \
                 ('yes', 'true', 'on'):
            iport = int(cfg.get('honeypot', 'interact_port'))
            from cowrie.core import interact
            svc = internet.TCPServer(iport, interact.makeInteractFactory(factory))
            svc.setServiceParent(top_service)

        application = service.Application('cowrie')
        top_service.setServiceParent(application)
        return top_service


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = CowrieServiceMaker()
