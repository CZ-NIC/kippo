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
* add uname -r command
* add working sleep command
* enabled ssh diffie-hellman-group-exchange-sha1 algorithm
* add 'bash -c' support (no effect option)
* enable support for && multiple commands
* create uuid to uniquely identify each session
* log and deny direct-tcpip attempts 
* add "chattr" command
* support emacs keybindings (c-a, c-b, c-f, c-p, c-n, c-e)
* add "sync" command
* accept, log and deny public key authentication
* add "uname -r" support
* logstash and kibana config files added, based on JSON log
* fix for honeypot detection (pre-auth differences with openssh)
* fixes for behavior with non-existent files (cd /test, cat /test/nonexistent, etc)
* fix for ability to ping/ssh non-existent IP address
