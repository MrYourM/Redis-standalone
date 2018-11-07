#!/bin/bash
# Script to stop keepalived.

PID=$(pidof keepalived)
if [ -z "$PID" ]; then
    echo "keepalived is not running" > /var/log/keepalived.log 2>&1
    exit 0
fi

# Try to terminate keepalived
kill -SIGTERM $PID

# Check if keepalived is terminated
for i in $(seq 0 2); do
   if ! ps -ef | grep ^stop-keepalived > /dev/null; then
       echo "keepalived is successfully terminated" >> /var/log/keepalived.log 2>&1
       exit 0
   fi
   sleep 1
done

# Not terminated yet, now I am being rude!
# In case of a new keepalived process is somebody else (unlikely though),
# we get the pid again here.
kill -9 $(pidof keepalived)
if [ $? -eq 0 ]; then
    echo "keepalived is successfully killed" >> /var/log/keepalived.log 2>&1
    exit 0
else
    echo "Failed to kill keepalived" >> /var/log/keepalived.log 2>&1
    exit 1
fi
