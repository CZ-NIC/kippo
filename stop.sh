#!/bin/sh

PIDFILE=cowrie.pid
PID=$(cat $PIDFILE 2>/dev/null)
if [ -n "$PID" ]; then
    echo "Stopping Cowrie .."
    kill -TERM $PID
fi 
