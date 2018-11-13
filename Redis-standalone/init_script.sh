#!/bin/bash
chmod +x ./bin/*
mkdir -p /opt/app/bin/
mkdir -p /usr/local/sbin/
mkdir -p /etc/systemd/system/
echo "
#
# keepalived control files for systemd
#
# Incorporates fixes from RedHat bug #769726.

[Unit]
Description=Redis Monitor
After=network.target

[Service]
Type=simple
# Ubuntu/Debian convention:
ExecStart=/usr/local/sbin/redis-mon 1000
ExecReload=/bin/kill -s HUP $MAINPID
# keepalived needs to be in charge of killing its own children.
KillMode=process
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/redis-mon.service


cp ./bin/ctl.sh /opt/app/bin/
cp ./bin/redis-mon /usr/local/sbin/
cp ./bin/*.py /opt/redis/
cp ./bin/notify.sh /opt/redis/
cp ./bin/*.sh /opt/redis/bin/
rm -rf /opt/redis/bin/notify.sh

cp ./confd/conf.d/* /etc/confd/conf.d/
cp ./confd/templates/* /etc/confd/templates/


pip install os
pip install json
pip install urllib2
pip install logging
pip install subprocess
pip install time
pip install sys
pip install signal
pip install errno
pip install datetime
pip install shutil


pip install redis

wget https://files.pythonhosted.org/packages/74/bb/9003d081345e9f0451884146e9ea2cff6e4cc4deac9ffd4a9ee98b318a49/hashlib-20081119.zip
unzip hashlib-20081119.zip
cd hashlib-20081119/
python setup.py install
cd ..
rm -rf ./hash*