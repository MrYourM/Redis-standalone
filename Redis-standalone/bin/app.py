#!/usr/bin/python
#coding=utf-8
import commands
import os
import json
import urllib2
import logging
import logging.handlers
import subprocess
import time
import sys
import signal
import errno
import datetime
import shutil
import hashlib

import redis
from monitor import Monitor
from Config import Config
import Constants

class App:
    def __init__(self):
        self.logger = None
        self.config = Config(Constants.DATA_HOME + "/gen/redis.conf")
        self.redis_conf_path = Constants.DATA_HOME + "/redis.conf"
        self.__init_logger("REDIS", Constants.DATA_HOME)
        
    def __prepare_conf(self):
        if not os.path.isfile(self.redis_conf_path):
            shutil.copyfile(Constants.DATA_HOME + "/gen/redis.conf", self.redis_conf_path)
        if not os.path.isfile(Constants.KEEPALIVED_CONF_FILE):
            shutil.copy(Constants.KEEPALIVED_COPY_CONF_FILE,Constants.KEEPALIVED_CONF_FILE)

        self.__reconfigure_conf(self.redis_conf_path, redis_conf=True)

    def __reconfigure_conf(self, conf_file_path, redis_conf=True):
        self.logger.info("Reconfigure %s with master [%s, %s]" % (conf_file_path, self.config.get_master_ip(), self.config.get_master_port()))

        output_config = []

        fd = open(conf_file_path, 'r')

        for line in fd:
            newline = line
            if redis_conf:
                if line.startswith("slaveof") \
                    or line.startswith("requirepass") \
                    or line.startswith("masterauth") \
                    or line.startswith("rename-command") \
                    or line.startswith("maxmemory_portion") \
                    or line.startswith("enable-commands"):
                    continue

            output_config.append(newline)
        
        # Add extra configuration
        if redis_conf:
            for command in Constants.DISABLE_COMMANDS:
                if command not in self.config.enable_commands:
                    newline = "rename-command %s %s\n" % (command, hashlib.sha256(command + self.config.get_cluster_id()).hexdigest())
                    output_config.append(newline)
            
            if not self.config.is_master():
                newline = "slaveof %s %s\n" % (self.config.get_master_ip(), self.config.get_master_port())
                output_config.append(newline)
            
            if self.config.is_requirepass():
                newline = "requirepass %s\n" % self.config.get_password()
                if not self.config.is_master():
                    tmp = "masterauth %s\n" % self.config.get_password()
                    newline = newline + "\n" + tmp
                output_config.append(newline)
        fd.close()
        open(conf_file_path, "w").close()
        fd = open(conf_file_path, "w")
        fd.writelines(output_config)
        fd.close()

        if self.config.is_master():
            output_config = []
            fd = open(Constants.KEEPALIVED_COPY_CONF_FILE, "r")
            for line in fd:
                if line.lstrip().startswith('priority'):
                    output_config.append("    priority 100\n")
                    output_config.append("    nopreempt\n")
                    continue
                output_config.append(line)
            fd.close()
            with open(Constants.KEEPALIVED_CONF_FILE,'w') as f:
                f.writelines(output_config)

    
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
    
    def __add_passphrase(self):
        host_passphrases = self.config.get_hosts_passphrase()
        pub_key = None
        if os.path.isfile(Constants.AUTHORIZED_KEYS_FILE):
            fd = open(Constants.AUTHORIZED_KEYS_FILE, "r")
            pub_key = fd.readline()
            fd.close()
            open(Constants.AUTHORIZED_KEYS_FILE, "w").close() # clear content
        
        fd = open(Constants.AUTHORIZED_KEYS_FILE, "w")
        if pub_key is not None:
            fd.write("%s\n" % pub_key)
        for passphrase in host_passphrases:
            fd.write("%s\n" % passphrase)
        fd.close()

    def __single_node_start(self,from_who=None):
        if from_who != None:
            self.logger.info("Start request from {}".format(from_who))
        self.__prepare_conf()


        if not self.__check_process_alive("redis-server"):
            start_server_cmd = Constants.REDIS_HOME + "/bin/redis-server " + self.redis_conf_path
            process = self.__exec_cmd(start_server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if not self.__check_process_alive('keepalived'):
            start_keepalived_cmd = "{} -f {}".format(Constants.KEEPALIVED_FILE, Constants.KEEPALIVED_CONF_FILE)
            self.__exec_cmd(start_keepalived_cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # if self.config.is_master() and not self.__is_vip_binded():
            # self.__bind_vip()

        self.__apply_new_config()


    def start(self):
        self.logger.info(" =========== Start ========== ")
        self.__prepare_conf()

        self.__add_passphrase()
        if not self.config.will_be_deleted() and self.config.is_master(exclude=False):
            self.logger.warn("start master")
            redis_cmd = Constants.REDIS_HOME + "/bin/redis-server " + self.redis_conf_path
            process_redis = self.__exec_cmd(redis_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            keepalived_cmd = "{} -f {}".format(Constants.KEEPALIVED_FILE, Constants.KEEPALIVED_CONF_FILE)
            process_keepalived = self.__exec_cmd(keepalived_cmd,  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.warn("start slave")
            if process_redis.returncode == 0 and process_keepalived.returncode == 0:
                self.__apply_new_config()
                start_slave_cmd = "'/opt/redis/app.py action {}'".format(self.config.get_node_ip())
                self.__exec_other_nodes_cmd(start_slave_cmd)

    
    def stop(self, scale_in=False):
        self.logger.warn(" =========== Stop ========== ")

        if not self.config.will_be_deleted() and self.config.is_master(exclude=True):
            self.logger.info("Stop slaves")
            cmd = "'/opt/redis/app.py force_stop {}'".format(self.config.get_node_ip())
            self.__exec_other_nodes_cmd(cmd)

            self.__stop()
        elif self.config.will_be_deleted():
            self.__stop()

        self.logger.info("Stop completed")
    
    def force_stop(self, from_who=None):
        if from_who is not None:
            self.logger.info("Stop request from %s" % from_who)
        
        self.__stop()
    
    def __stop(self):
        # if self.config.is_master() and self.__is_vip_binded():
        #     vip = self.config.get_vip()
        #     unbind_cmd = "/sbin/ip addr del %s/24 dev eth0" % vip
        #     process = self.__exec_cmd(unbind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # # remove sentinel first, in case of failover during stop
        # if self.__check_process_alive("redis-sentinel"):
        #     try:
        #         rd = None
        #         if self.config.is_requirepass():
        #             rd = redis.StrictRedis(host=self.config.get_node_ip(), port=self.config.get_master_port(), password=self.config.get_password())
        #         else:
        #             rd = redis = redis.StrictRedis(host=self.config.get_node_ip(), port=self.config.get_master_port())
        #         rd.sentinel_remove(Constants.REDIS_SENTINEL_NAME)
        #     except Exception,ex:
        #         self.logger.error(ex)

        if self.__check_process_alive('keepalived'):
            stop_keepalived_cmd = Constants.REDIS_HOME + "/bin/stop-keepalived.sh"
            self.__exec_cmd(stop_keepalived_cmd)
        stop_server_cmd = Constants.REDIS_HOME + "/bin/stop-redis-server.sh"
        process = self.__exec_cmd(stop_server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        self.__save_to_master_file()

        if os.path.isfile(Constants.MONITOR_FILE):
            os.remove(Constants.MONITOR_FILE)


    def check(self):
    
        if not self.__check_process_alive("redis-server"):
            self.logger.warn("Redis Server process is down")
            return False

        if self.config.is_master(exclude=True):

            if not self.__is_vip_binded():
                return False

        if self.__is_vip_binded():
            if not self.config.is_master(exclude=True):
                return False


        if not self.__check_process_alive('keepalived'):
            return False
        return True

    
    def action(self,from_who=None):
        self.__single_node_start(from_who)

    def scale_in(self):
        if self.config.will_be_deleted():
            return
        
        if os.path.isfile(Constants.MASTER_FILE):
            os.remove(Constants.MASTER_FILE)

        if not self.config.is_master():
            self.config.refresh()
            self.stop()
            self.start()
    
    def scale_out(self):
        if self.config.is_master():
            self.stop()
            self.start()
    
    def test_conf(self):
        self.__prepare_conf()
    
    def monitor(self):
        mon = Monitor(require_pass=self.config.is_requirepass(), password=self.config.get_password())
        result = mon.collect_data()
        print json.dumps(result)
    
    def print_config(self):
        print self.config.json()

    def __save_to_master_file(self):
        self.logger.info(" ======== Save master to file ========= ")
        with open(Constants.MASTER_FILE, "w") as fd:
            fd.write("%s %s\n" % (self.config.get_master_ip(), self.config.get_master_port()))
    def __bind_vip(self):
        vip = self.conf.get_vip()
        cmd = "/sbin/ip addr add %s/24 dev eth0" % vip
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            self.logger.info("Bind vip %s successfully" % vip)

    def __is_vip_binded(self):
        vip = self.config.get_vip()
        cmd = "/sbin/ip a | grep %s" % vip
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            self.logger.info("VIP has already been binded");
            return True
        return False

    def __check_process_alive(self, proc_name, use_ps=False):
        cmd = "pidof " + proc_name
        if use_ps:
            cmd = "ps -ef | grep " + proc_name + " | grep -v grep"
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            return True

        return False

    def __exec_cmd(self, command, timeout=None, stdout=None, stderr=None, stdin=None):
        """

        """
        start = datetime.datetime.now()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if timeout is not None and (now - start).seconds > timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                #pipout = '\n'.join([s.read() for s in [process.stdout, process.stderr] if s is not None])
                self.logger.warn("Executing [%s] TIMOUT, killed the process" % command)
        
        if process is not None and process.returncode != 0:
            self.logger.info("Executing [%s]" % command)
            out, err = process.communicate()
            pipout = ' '.join([out, err])
            self.logger.error("[retcode %d] %s" % (process.returncode, pipout))

        return process
    
    def __apply_new_config(self):
        if not os.path.isfile(Constants.DATA_HOME + "/gen/redis.conf.update"):
            shutil.copyfile(Constants.DATA_HOME + "/gen/redis.conf", Constants.DATA_HOME + "/gen/redis.conf.update")
        
        old_config = self.__get_config(Constants.DATA_HOME + "/gen/redis.conf.update")
        new_config = self.__get_config(Constants.DATA_HOME + "/gen/redis.conf")

        update_config = {}
        for key, value in new_config.iteritems():
            if new_config[key] != old_config[key]:
                update_config[key] = value

        self.logger.info(update_config)
        
        if self.__check_process_alive("redis-server") and len(update_config) > 0:
            config_command = "config"
            if "CONFIG" not in self.config.enable_commands:
                config_command = hashlib.sha256("CONFIG" + self.config.get_cluster_id()).hexdigest()

            for key, value in update_config.iteritems():
                if self.config.is_requirepass():
                    cmd = "%s/bin/redis-cli -a %s %s set %s %s" % (Constants.REDIS_HOME, self.config.get_password(), config_command, key, value)
                else:
                    cmd = "%s/bin/redis-cli %s set %s %s" % (Constants.REDIS_HOME, config_command, key, value)
                process = self.__exec_cmd(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            self.logger.info("going to rewrite")
            rewrite_cmd = "%s/bin/redis-cli %s rewrite" % (Constants.REDIS_HOME, config_command)
            process = self.__exec_cmd(rewrite_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
            shutil.copyfile(Constants.DATA_HOME + "/gen/redis.conf", Constants.DATA_HOME + "/gen/redis.conf.update")
    
    def __get_config(self, config_file_path):
        fd = open(config_file_path, "r")
        config = {}
        for line in fd:
            if line.startswith("slaveof") \
                or line.startswith("rename-command") \
                or line.startswith("requirepass") \
                or line.startswith("enable-commands") \
                or line.startswith("maxmemory_portion") \
                or line.startswith(" "):
                continue
            line = line.strip()
            items = line.split(' ')
            if len(items) > 1:
                config[items[0]] = ' '.join(items[1:])
        fd.close()
        return config

    def __exec_other_nodes_cmd(self,cmd):
        for host in self.config.get_hosts():
            if self.config.get_node_ip() != host['ip']:
                enable_exec_cmd = 'ssh root@{} '.format(host['ip']) + cmd
                self.__exec_cmd(enable_exec_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            continue




if __name__=="__main__":
    app = App()

    if len(sys.argv) > 1:
        command = sys.argv[1]
        if len(sys.argv) > 2:
            argument = sys.argv[2]

        if command == "start":
            app.start()
        elif command == "stop":
            app.stop()
        elif command == "check":
            if app.check():
                sys.exit(0)
            else:
                sys.exit(1)
        elif command == "action":
            if len(sys.argv) > 2:
                from_who = sys.argv[2]
            else:
                from_who = None
            app.action(from_who)

        elif command == "monitor":
            app.monitor()
        elif command == "restart":
            app.stop()
            app.start()
        elif command == "scale_in":
            app.scale_in()
        elif command == "force_stop":
            app.force_stop(from_who="192.168.0.4")
        elif command == "config":
            app.print_config()
        elif command == "test_config":
            app.test_conf()
