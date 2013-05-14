#!/bin/sh

PIDFILE=kippo.pid
PID=$(cat $PIDFILE 2>/dev/null)
if [ -n "$PID" ]; then
    echo "Stopping Kippo .."
    kill -TERM $PID
fi 
