This fork might not run on OpenSUSE 11.4 (works fine on 13.1).
In that case, dispose commit a693fb18da384ecbf71fdb1b2178292133c4a9ac (Fix kippo sandbox detecting).

* log and deny direct-tcpip attempts (micheloosterhof)
* change exec handling so the command is allowed to run long enough for wget to work (desaster)
* 2015-02-20 Removed screen clear/reset on logout
* default behaviour is changed to disable the exit jail
* sftp support
* exec support
* stdin is saved as a file in dl/ when using exec commands
    to support commands like 'cat >file; ./file'
* allow wget download over non-80 port
* simple JSON logging added
* accept log and deny publickey authentication
* add uname -r, -m flags
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
* always send ssh exit-status 0 on exec and shell
* ls output is now alphabetically sorted
* banner_file is deprecated. honeyfs/etc/issue.net is default
* add 'dir' alias for 'ls'
* add 'help' bash builtin
* add 'users' aliased to 'whoami'
* add 'killall' and 'killall5' aliased to nop
* add 'poweroff' 'halt' and 'reboot' aliases for shutdown
* add environment passing to commands
* added 'which', 'netstat' and 'gcc' from kippo-extra
