# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from sys import modules

from zope.interface import implements

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import ISSHPrivateKey
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials

from twisted.internet import defer
from twisted.python import log, failure
from twisted.conch import error
from twisted.conch.ssh import keys

from cowrie.core.config import config
from cowrie.core import credentials
from cowrie.core import auth

class HoneypotPublicKeyChecker:
    implements(ICredentialsChecker)
    """
    Checker that accepts, logs and denies public key authentication attempts
    """

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)
        log.msg( 'Public Key attempt for user %s with fingerprint %s' % ( credentials.username, _pubKey.fingerprint() ) )
        return failure.Failure(error.ConchError("Incorrect signature"))

class HoneypotNoneChecker:
    implements(ICredentialsChecker)
    """
    Checker that does no authentication check
    """

    credentialInterfaces = (credentials.IUsername,)

    def __init__(self):
        pass

    def requestAvatarId(self, credentials):
        return defer.succeed(credentials.username)

class HoneypotPasswordChecker:
    implements(ICredentialsChecker)
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (credentials.IUsernamePasswordIP,
        credentials.IPluggableAuthenticationModulesIP)

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password,
                                  credentials.ip):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                                     credentials.pamConversion, credentials.ip)
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion, ip):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username, ip)

    def cbCheckPamUser(self, responses, username, ip):
        for (response, zero) in responses:
            if self.checkUserPass(username, response, ip):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, theusername, thepassword, ip):
        #  UserDB is the default auth_class
        authname = auth.UserDB
        parameters = None

        # Is the auth_class defined in the config file?
        if config().has_option('honeypot', 'auth_class'):
            authclass = config().get('honeypot', 'auth_class')

            # Check if authclass exists in this module
            if hasattr(modules[__name__], authclass):
                authname = getattr(modules[__name__], authclass)

                # Are there auth_class parameters?
                if config().has_option('honeypot', 'auth_class_parameters'):
                    parameters = config().get('honeypot', 'auth_class_parameters')
            else:
                log.msg('auth_class: %s not found in %s' % (authclass, __name__))

        if parameters:
            theauth = authname(parameters)
        else:
            theauth = authname()

        if theauth.checklogin(theusername, thepassword, ip):
            log.msg( 'login attempt [%s]/[%s] succeeded' % (theusername, thepassword) )
            return True
        else:
            log.msg( 'login attempt [%s]/[%s] failed' % (theusername, thepassword) )
            return False

# vim: set sw=4 et:
