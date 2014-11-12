* log and deny direct-tcpip attempts (micheloosterhof)
* change exec handling so the command is allowed to run long enough for wget to work (desaster)
* default behaviour is changed to disable the exit jail
* sftp support
* exec support
* stdin is saved as a file in dl/ when using exec commands
    to support commands like 'cat >file; ./file'
* allow wget download over non-80 port
* simple JSON logging to kippo.json
* accept log and deny publickey authentication
