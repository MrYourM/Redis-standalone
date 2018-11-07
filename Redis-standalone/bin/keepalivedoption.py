#!/usr/bin/python
#coding=utf-8

import commands
import hashlib
import json
import os
import subprocess
import sys
import urllib2

from Config import Config
import Constants

class KeepalivedOption:

    def __init__(self):
        self.config = Config(Constants.DATA_HOME + "/gen/redis.conf")
        self.command = hashlib.sha256('SLAVEOF' + self.config.get_cluster_id()).hexdigest() + ' '
        self.peer_ip = get_peer_ip()
        self.port = self.config.node.port
        self.__start()

    def __start(self):
        if self.config.is_requirepass():
            self.__redis_cli = '/opt/redis/bin/redis-cli -a {} '.format({self.config.requirepass})
        else:
            self.__redis_cli = '/opt/redis/bin/redis-cli '

    def redis_backup(self):
        # 转变为backup
        cmd = self.__redis_cli + self.command + self.peer_ip + ' ' + self.port
        os.system(cmd)

    def redis_check(self):
        cmd = self.__redis_cli + 'PING'
        print cmd
        result = run_cmd(cmd)
        print result
        if result.strip() == 'PONG':
            sys.exit(0)
        else:sys.exit(1)

    def redis_fault(self):
        # 故障
        print 'fault'

    def redis_master(self):
        # 转变为standby
        cmd = self.__redis_cli + self.command +'NO ONE'
        (status, output) = commands.getstatusoutput(cmd)
        if status == 0:
            print 'slaveof no one success'
        else:
            print 'slaveof no one fail'

    def redis_stop(self):
        # redis停止
        print 'redis stop'


def get_request(url, json_format=True):
    """
    请求metadata数据
    :param url:
    :param json_format:
    :return:
    """
    format_headers = {}
    if json_format:
        format_headers = {"Accept": "application/json"}

    try:
        request = urllib2.Request(url, headers=format_headers)
        contents = urllib2.urlopen(request).read()
    except Exception, ex:
        if json_format:
            return {"code": 404, "message": "Not found", "type": "ERROR"}
        else:
            return "Not found"

    if json_format:
        return json.loads(contents)
    else:
        return contents


def get_hosts(refresh=False):
    hosts_dict = get_request("http://metadata/self/hosts/node")
    hosts = []
    response = {}

    if refresh:
        response = get_request("http://metadata/self/deleting-hosts")

    for key, value in hosts_dict.iteritems():
        if ('code' in response and response['code'] == 404) or key not in response:
            hosts.append(value)

    return hosts


def get_peer_ip():
    """
    获得另一个节点的ip
    :return:
    """
    node_ip = get_request(url='http://metadata/self/host/ip')
    hosts = get_hosts(refresh=True)
    if len(hosts) != 2:
        return
    else:
        for host_info in hosts:
            if host_info['ip'] != node_ip:
                peer_ip = host_info['ip']
                break
        return peer_ip


def run_cmd(cmd, verbose=False):
    """
    执行cmd并返回标准输出,若verbose为True,则其输出或者错误写入日志
    :param cmd:
    :param verbose:
    :return:
    """
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out, error = p.communicate()
    # logging.info('run cmd: %s' % cmd)
    if verbose:
        pass
        # logging.info('out is %s' % out)
        # logging.info('error is %s' % error)
    return out.decode('utf-8')


if __name__ == '__main__':
    command = sys.argv[1]
    keepalived_option = KeepalivedOption()
    if command == 'redis_backup':
        keepalived_option.redis_backup()
    elif command == 'redis_check':
        keepalived_option.redis_check()
    elif command == 'redis_fault':
        keepalived_option.redis_fault()
    elif command == 'redis_master':
        keepalived_option.redis_master()
    elif command == 'redis_stop':
        keepalived_option.redis_stop()
    elif command == 'test':
        print get_peer_ip()




