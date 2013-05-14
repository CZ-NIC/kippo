#!/bin/sh

PIDFILE=kippo.pid
PID=$(cat $PIDFILE)

echo "Stopping Kippo .."
kill -TERM $PID
