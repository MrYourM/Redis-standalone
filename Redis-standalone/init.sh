#!/bin/sh
echo "deb http://mirrors.aliyun.com/ubuntu/ xenial main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial main

deb http://mirrors.aliyun.com/ubuntu/ xenial-updates main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates main

deb http://mirrors.aliyun.com/ubuntu/ xenial universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial universe
deb http://mirrors.aliyun.com/ubuntu/ xenial-updates universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-updates universe

deb http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security main
deb http://mirrors.aliyun.com/ubuntu/ xenial-security universe
deb-src http://mirrors.aliyun.com/ubuntu/ xenial-security universe" > /etc/apt/sources.list

apt update

wget http://appcenter-docs.qingcloud.com/developer-guide/scripts/app-agent-linux-amd64.tar.gz
tar xzf app-agent-linux-amd64.tar.gz
cd app-agent-linux-amd64
./install.sh
cd
rm -rf app-agent-linux-amd64*

apt install python-pip

wget http://download.redis.io/releases/redis-5.0.0.tar.gz
tar zxvf redis-5.0.0.tar.gz
cd redis-5.0.0
make
mv ./src ./bin
cd ~
mv ./redis-5.0.0 /opt/redis
rm -f redis-5.0.0.tar.gz

apt install unzip
