#!/bin/sh

echo "Starting cowrie in background..."
nohup twistd -y cowrie.tac -l log/cowrie.log --pidfile cowrie.pid
