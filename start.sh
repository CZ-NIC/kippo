#!/bin/sh

echo "Starting cowrie in the background..."
nohup twistd -l log/cowrie.log --pidfile cowrie.pid cowrie
