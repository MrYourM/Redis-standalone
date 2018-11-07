#!/bin/bash
apt install unzip
chmod +x ./bin/*
cp ./bin/*.py /opt/redis/
cp ./bin/notify.sh /opt/redis/
cp ./bin/*.sh /opt/redis/bin/
rm -rf /opt/redis/bin/notify.sh

cp ./confd/conf.d/* /etc/confd/conf.d/
cp ./confd/templates/* /etc/confd/templates/
mv /opt/redis/bin/redis_*.sh /opt/redis/

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