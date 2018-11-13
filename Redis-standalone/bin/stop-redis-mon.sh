#!/bin/bash
# Script to stop redis-mon.

PID=$(pidof redis-mon)
if [ -z "$PID" ]; then
    echo "redis-mon is not running" > /var/log/redis-mon.log 2>&1
    exit 0
fi

# Try to terminate redis-mon
kill -SIGTERM $PID

# Check if redis-mon is terminated
for i in $(seq 0 2); do
   if ! ps -ef | grep ^stop-redis-mon > /dev/null; then
       echo "redis-mon is successfully terminated" >> /var/log/redis-mon.log 2>&1
       exit 0
   fi
   sleep 1
done

# Not terminated yet, now I am being rude!
# In case of a new redis-mon process is somebody else (unlikely though),
# we get the pid again here.
kill -9 $(pidof redis-mon)
if [ $? -eq 0 ]; then
    echo "redis-mon is successfully killed" >> /var/log/redis-mon.log 2>&1
    exit 0
else
    echo "Failed to kill redis-mon" >> /var/log/redis-mon.log 2>&1
    exit 1
fi
