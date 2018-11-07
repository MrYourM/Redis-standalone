#!/usr/bin/python
#coding=utf-8
import commands
import os
import json
import urllib2
import logging.handlers
import subprocess
import time
import sys
import signal
import errno
import datetime
import shutil
import hashlib
import Constants

class Config:
    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.enable_commands = []
        self.requirepass = False
        self.password = None
        self.node = Node()
        self.logger = None
        self.maxmemory_portion = Constants.MAX_MEMORY_PERCENTAGE
        self.__init_logger("REDIS", Constants.DATA_HOME)

        ip, port = self.__get_master()
        self.master_ip = ip
        self.master_port = port
        self.master_node_id = None

        self.__parse_config()
    
    def json(self):
        return {'config_file_path': self.config_file_path,\
                'enable_commands' : self.enable_commands,\
                'requirepass' : self.requirepass,\
                'password' : self.password,\
                'master_ip' : self.master_ip,\
                'self_ip' : self.node.get_ip(), \
                'is_master' : self.is_master(), \
                'master_port' : self.master_port}

    def refresh(self):
        ip, port = self.__get_master(update=True)
        self.master_ip = ip
        self.master_port = port
        self.logger.info("After refresh %s %s" %(self.master_ip, self.master_port))

    def get_hosts_count(self, update=False):
        return len(self.__get_hosts(refresh=update))
    
    def get_node_memory(self):
        return int(self.node.get_memory())
    
    def is_requirepass(self):
        return self.requirepass
    
    def get_password(self):
        return self.password
    
    def is_master(self, exclude=False):
        if exclude:
            self.refresh()
        return self.node.get_ip() == self.master_ip
    
    def get_master_ip(self):
        return self.master_ip
    
    def get_master_port(self):
        return self.master_port
    
    def get_node_id(self):
        return self.master_node_id
    
    def get_node_ip(self):
        return self.node.get_ip()
    
    def will_be_deleted(self):
        response = self.__get_request("http://metadata/self/deleting-hosts")
        if ('code' in response and response['code'] == 404) or self.node.node_id not in response:
            return False
        return True
    
    def get_hosts_passphrase(self):
        hosts = self.__get_hosts()

        passphrases = []
        for host in hosts:
            passphrase = self.__get_request("http://metadata/self/hosts/node/%s/pub_key" % host['instance_id'])
            if passphrase.startswith("ssh-rsa"):
                passphrases.append(passphrase)
        
        return passphrases

    def __parse_config(self):
        if not os.path.isfile(self.config_file_path):
            raise Exception

        fd = open(self.config_file_path, 'r')

        for line in fd:
            if line.startswith("requirepass") or line.startswith("masterauth"):
                items = line.strip().split(' ')
                if len(items) == 2:
                    if len(items[1].replace('"', '')) > 0:
                        self.requirepass = True
                        self.password = items[1].replace('"', '')

            elif line.startswith("enable-commands"):
                line = line.strip().split(' ')[1]
                commands = line.split(',')
                for command in commands:
                    if command == Constants.DISABLE_ALL:
                        self.enable_commands = []
                        break
                    else:
                        self.enable_commands.append(command)
            
            elif line.startswith("maxmemory_portion"):
                items = line.strip().split(' ')
                if len(items) == 2:
                     self.maxmemory_portion = float(items[1]) / 100


    def __get_master(self, update=False):
        """
                如果为主节点：
                output为
                # Replication
                role:master
                connected_slaves:2
                slave0:ip=192.168.128.13,port=6379,state=online,offset=1384374,lag=0
                slave1:ip=192.168.128.14,port=6379,state=online,offset=1384374,lag=0
                master_replid:77cc085efc55dcbc6c218026cebda56eefbad149
                master_replid2:0000000000000000000000000000000000000000
                master_repl_offset:1384374
                second_repl_offset:-1
                repl_backlog_active:1
                repl_backlog_size:1048576
                repl_backlog_first_byte_offset:335799
                repl_backlog_histlen:1048576
                若为从节点:
                output为
                # Replication
                role:slave
                master_host:192.168.128.12
                master_port:6379
                master_link_status:up
                master_last_io_seconds_ago:0
                master_sync_in_progress:0
                slave_repl_offset:1351579
                slave_priority:100
                slave_read_only:1
                connected_slaves:0
                master_replid:77cc085efc55dcbc6c218026cebda56eefbad149
                master_replid2:0000000000000000000000000000000000000000
                master_repl_offset:1351579
                second_repl_offset:-1
                repl_backlog_active:1
                repl_backlog_size:1048576
                repl_backlog_first_byte_offset:303004
                repl_backlog_histlen:1048576

                """

        # 1、获取自身节点ip
        master_ip = self.node.get_ip()
        master_port = self.node.get_port()
        master_node_id = self.node.get_node_id()

        hosts = self.__get_hosts(refresh=update)
        hosts_ips = []
        for host in hosts:
            hosts_ips.append(host['ip'])
        # 2、获取第一个节点ip，刚开始创建时的master_ip
        if len(hosts) > 0:
            master_ip = hosts[0]['ip']
            master_node_id = hosts[0]['node_id']
         # 3、获取MASTER_FILE中的ip ,用于重启的redis服务时对master_ip的读取
        if os.path.isfile(Constants.MASTER_FILE):
            fd = open(Constants.MASTER_FILE, "r")
            temp_ip, temp_port = fd.readline().split(' ')
            fd.close()
            if temp_ip in hosts_ips:
                master_ip, master_port = temp_ip, temp_port
            else:
                os.remove(Constants.MASTER_FILE)
        if len(self.get_hosts()) == 2:
            if self.is_requirepass():
                self_cmd = "/opt/redis/bin/redis-cli -a {} info replication".format(self.get_password())
                peer_cmd = "/opt/redis/bin/redis-cli -a {} -h {} info replication".format(self.get_password(),self.get_peer_ip())
            else:
                self_cmd = "/opt/redis/bin/redis-cli info replication"
                peer_cmd = "/opt/redis/bin/redis-cli -h {} info replication".format(self.get_peer_ip())
            cli_get_ip = None
            cli_port  = None
            status,output = commands.getstatusoutput(self_cmd)
            if status == 0:
                for info in output.split('\n'):
                    if info.strip().startswith('role'):
                        if info.strip().split(':')[1] == 'master':
                            cli_get_ip,cli_port = self.get_node_ip(),self.node.get_port()
                            break
                master_ip, master_port = cli_get_ip, cli_port
            if cli_get_ip == None and cli_port ==None:
                status,output = commands.getstatusoutput(peer_cmd)
                if status == 0:
                    for info in output.split('\n'):
                        if info.strip().startswith('role'):
                            if info.strip().split(':')[1] == 'master':
                                cli_get_ip,cli_port = self.get_peer_ip(),self.node.get_port()
                                break
                    master_ip, master_port = cli_get_ip, cli_port
        return master_ip, master_port
    
    def get_vip(self):
        return self.__get_request("http://metadata/self/cluster/endpoints/reserved_ips/vip/value", json_format=False)

    def get_hosts(self, exclude=False):
        return self.__get_hosts(refresh=exclude)

    # def __get_master_hosts(self,refresh=False):
    #     hosts_dict = self.__get_request("http://metadata/self/hosts/master")
    #     hosts = []
    #     response = {}
    #
    #     if refresh:
    #         response = self.__get_request("http://metadata/self/deleting-hosts/master")
    #
    #     for key, value in hosts_dict.iteritems():
    #         if ('code' in response and response['code'] == 404) or key not in response:
    #             hosts.append(value)
    #     return hosts

    def __get_hosts(self, refresh=False):
        hosts_dict = self.__get_request("http://metadata/self/hosts/node")
        hosts = []
        # excep_response = self.__get_request("http://metadata/self/adding-hosts")
        response = {}

        if refresh:
            response = self.__get_request("http://metadata/self/deleting-hosts")

        for key, value in hosts_dict.iteritems():
            if ('code' in response and response['code'] == 404) or key not in response:
                hosts.append(value)
        return hosts

    def get_peer_ip(self):
        """
        获得另一个节点的ip
        :return:
        """
        node_ip = self.__get_request(url='http://metadata/self/host/ip')
        hosts = self.__get_hosts(refresh=True)
        if len(hosts) != 2:
            return
        else:
            for host_info in hosts:
                if host_info['ip'] != node_ip:
                    peer_ip = host_info['ip']
                    break
            return peer_ip
    
    def get_cluster_id(self):
        return self.__get_request("http://metadata/self/cluster/cluster_id", json_format=False)
            
    def __get_request(self, url, json_format=True):
        format_headers = {}
        if json_format:
            format_headers = {"Accept" : "application/json"}

        try:
            request = urllib2.Request(url, headers = format_headers)
            contents = urllib2.urlopen(request).read()
        except Exception, ex:
            self.logger.error("%s : %s" % (url, ex))
            if json_format:
                return {"code" : 404, "message" : "Not found", "type" : "ERROR"}
            else:
                return "Not found"

        if json_format:
            return json.loads(contents)
        else:
            return contents
    
    def __init_logger(self, logger_name, log_dir):
        if not os.path.isdir(log_dir):
            os.system("mkdir -p %s; chmod 755 %s" % (log_dir, log_dir))
        app_deploy_log = "%s/%s.log" % (log_dir, logger_name)
        Rthandler = logging.handlers.RotatingFileHandler(app_deploy_log, maxBytes = 20 * 1024 * 1024, backupCount = 5)
        formatter = logging.Formatter('%(asctime)s -%(thread)d- [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
        Rthandler.setFormatter(formatter)

        self.logger = logging.getLogger('redis')
        self.logger.addHandler(Rthandler)
        self.logger.setLevel(logging.INFO)

class Node:
    
    def __init__(self):
        self.ip = None
        self.memory = None
        self.node_id = None
        self.mac = None
        self.port = None

        response = self.__get_request("http://metadata/self/host")

        self.ip = response["ip"]
        self.memory = response["memory"]
        self.node_id = response["node_id"]
        self.mac = response["mac"]

        response = self.__get_request("http://metadata/self/env/port", json_format=False)

        self.port = response
    
    def __get_request(self, url, json_format=True):
        format_headers = {}
        if json_format:
            format_headers = {"Accept" : "application/json"}

        try:
            request = urllib2.Request(url, headers = format_headers)
            contents = urllib2.urlopen(request).read()
        except Exception, ex:
            
            if json_format:
                return {"code" : 404, "message" : "Not found", "type" : "ERROR"}
            else:
                return "Not found"

        if json_format:
            return json.loads(contents)
        else:
            return contents
    
    def get_memory(self):
        return self.memory
    
    def get_ip(self):
        return self.ip
    
    def get_node_id(self):
        return self.node_id

    def get_port(self):
        return self.port


