#!/usr/bin/python
# _*_coding: utf-8 _*_
import commands
import datetime
import hashlib
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from Config import Config
import Constants


class Check:
    def __init__(self):
        self.log = None
        self.__init_logger("REDIS-MON", Constants.DATA_HOME)  # 需添加日志名及其日志路径
        self.config = Config(Constants.DATA_HOME + "/gen/redis.conf")  # 需添加redis的路径
        self.__init_files()
        self.operation = Operation()

    def __init_logger(self, logger_name, log_dir):
        if not os.path.isdir(log_dir):
            os.system("mkdir -p %s; chmod 755 %s" % (log_dir, log_dir))
        app_deploy_log = "%s/%s.log" % (log_dir, logger_name)
        Rthandler = logging.handlers.RotatingFileHandler(app_deploy_log, maxBytes=20 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s -%(thread)d- [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
        Rthandler.setFormatter(formatter)

        self.logger = logging.getLogger('redis')
        self.logger.addHandler(Rthandler)
        self.logger.setLevel(logging.INFO)

    def __init_files(self):
        if self.config.get_node_ip() == self.config.get_hosts()[0]["ip"]:
            if not os.path.isfile(Constants.STATE_FILE):
                with open(Constants.STATE_FILE, 'w') as f:
                    f.write(self.config.get_master_ip())

    def __check_process_alive(self, proc_name, use_ps=False):
        """
        检查进程是否存在
        :param proc_name:
        :param use_ps:
        :return:
        """
        cmd = "pidof " + proc_name
        if use_ps:
            cmd = "ps -ef | grep " + proc_name + " | grep -v grep"
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            if not proc_name == 'redis-server':
                return True
            if self.operation.redis_check():
                return True
        return False

    def __check_port_release(self, ip, port):
        """
        判断节点端口是否可以使用
        :param ip:
        :param port:
        :return:
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((ip, port))
            self.logger.info('{}主机的端口{}可用'.format(ip, port))
            return True
        except:
            self.logger.warn('{}主机的端口{}不可用'.format(ip, port))
            return False

    def __exec_cmd(self, command, timeout=None, stdout=None, stderr=None, stdin=None):
        start = datetime.datetime.now()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if timeout is not None and (now - start).seconds > timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                self.logger.warn("Executing [%s] TIMOUT, killed the process" % command)

        if process is not None and process.returncode != 0:
            self.logger.info("Executing [%s]" % command)
            out, err = process.communicate()
            pipout = ' '.join([out, err])
            self.logger.error("[retcode %d] %s" % (process.returncode, pipout))
        return process

    def port_is_release(self, port):
        peer_ip = self.config.get_peer_ip()
        self.__check_port_release(peer_ip, port)

    def check_state_file(self):
        """
        可能会出现的结果
        Warning: Permanently added '192.168.0.9' (ECDSA) to the list of known hosts.
        192.168.0.10

        :return:
        """
        if self.config.is_first_node():
            cmd = "cat /data/redis/state"
            content = commands.getoutput(cmd)
            print content

    def __check_is_state_master(self):
        cmd = Constants.REDIS_HOME + "/trilateral-operations.py check_state_file"
        if not self.config.is_first_node():
            cmd = "ssh root@{} '{}'".format(self.config.get_hosts()[0]["ip"], cmd)
        state_master_ip = commands.getoutput(cmd).strip()
        if len(state_master_ip.split('\n')) > 1:
            state_master_ip = state_master_ip.split('\n')[1].strip()
        if state_master_ip == str(self.config.get_node_ip()):
            return True
        else:
            return False

    def __check_peer_process_alive(self, proc_name, use_ps=False):
        cmd = "ssh root@{} '{}'".format(self.config.get_peer_ip(), "pidof " + proc_name)
        if use_ps:
            cmd = "ssh root@{} '{}'".format(self.config.get_peer_ip(), "ps -ef | grep " + proc_name + " | grep -v grep")
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            if not proc_name == 'redis-server':
                return True
            if self.operation.redis_check(peer_check=True):
                return True
        return False

    def __is_vip_bind(self):
        vip = self.config.get_vip()
        cmd = "/sbin/ip a | grep %s" % vip
        process = self.__exec_cmd(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            self.logger.info("VIP has already been binded");
            return True
        return False

    def check_monitor(self):
        if len(self.config.get_hosts()) == 2:
            print 1
            if not self.__check_port_release(self.config.get_peer_ip(), 22):
                print 1.1
                if self.config.get_node_ip() == self.config.get_hosts()[0]["ip"]:
                    if not self.__check_process_alive("redis-server"):
                        sys.exit(1)
                    if not self.__check_is_state_master():
                        self.operation.bind_vip()
                        self.operation.redis_master()
                        self.operation.change_ip_to_master(self.config.get_node_ip())
                else:
                    if not self.__check_process_alive('redis-server'):
                        sys.exit(1)
                    if self.__is_vip_bind():
                        self.operation.unbind_vip()
                    if self.config.get_master_ip() == self.config.get_node_ip():
                        self.operation.redis_backup()
                    sys.exit(0)  # 仅表示该节点是正常的，但22端口还是有问题的

        if not self.__check_process_alive("redis-server", use_ps=True):
            print 2
            if not self.__check_is_state_master():
                self.operation.change_ip_to_master(self.config.get_peer_ip())
                self.operation.unbind_vip()
        if len(self.config.get_hosts()) == 2:
            if not self.__check_peer_process_alive("redis-server", use_ps=True):
                print 3
                if not self.__check_is_state_master():
                    self.operation.change_ip_to_master(self.config.get_node_ip())
                    self.operation.bind_vip()

        if not self.__check_is_state_master():
            print 4
            if self.__is_vip_bind():
                print 4.5
                self.operation.unbind_vip()
            if self.config.get_master_ip() == self.config.get_node_ip():
                print 4.6
                sys.exit(0)
            else:
                print 4.7
                self.operation.redis_backup()
                sys.exit(0)

        if not self.__is_vip_bind():
            print 8
            self.operation.bind_vip()
        if not self.config.get_master_ip() == self.config.get_node_ip():
            print 9
            self.operation.redis_master()
            sys.exit(0)
        else:
            print 9.1
            sys.exit(0)


class Operation:
    def __init__(self):
        self.logger = None
        self.__init_logger("REDIS-MON", Constants.DATA_HOME)
        self.config = Config(Constants.DATA_HOME + "/gen/redis.conf")  # 需要添加redis的配置路径
        self.command = hashlib.sha256('SLAVEOF' + self.config.get_cluster_id()).hexdigest() + ' '
        self.__start()

    def __init_logger(self, logger_name, log_dir):
        if not os.path.isdir(log_dir):
            os.system("mkdir -p %s; chmod 755 %s" % (log_dir, log_dir))
        app_deploy_log = "%s/%s.log" % (log_dir, logger_name)
        Rthandler = logging.handlers.RotatingFileHandler(app_deploy_log, maxBytes=20 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter('%(asctime)s -%(thread)d- [%(levelname)s] %(message)s (%(filename)s:%(lineno)d)')
        Rthandler.setFormatter(formatter)

        self.logger = logging.getLogger('redis')
        self.logger.addHandler(Rthandler)
        self.logger.setLevel(logging.INFO)

    def __start(self):
        if self.config.is_requirepass():
            self.__redis_cli = '/opt/redis/bin/redis-cli -a {} '.format({self.config.requirepass})
        else:
            self.__redis_cli = '/opt/redis/bin/redis-cli '

    def __exec_cmd(self, command, timeout=None, stdout=None, stderr=None, stdin=None):
        start = datetime.datetime.now()
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        while process.poll() is None:
            time.sleep(0.1)
            now = datetime.datetime.now()
            if timeout is not None and (now - start).seconds > timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                # pipout = '\n'.join([s.read() for s in [process.stdout, process.stderr] if s is not None])
                self.logger.warn("Executing [%s] TIMOUT, killed the process" % command)

        if process is not None and process.returncode != 0:
            self.logger.info("Executing [%s]" % command)
            out, err = process.communicate()
            pipout = ' '.join([out, err])
            self.logger.error("[retcode %d] %s" % (process.returncode, pipout))
        return process

    def change_ip_to_master(self, ip):
        cmd = "echo {} > {}".format(ip, Constants.STATE_FILE)
        if not self.config.is_first_node():
            cmd = "ssh root@{} '{}'".format(self.config.get_hosts()[0]["ip"], cmd)
        process = self.__exec_cmd(cmd)
        if process.returncode == 0:
            self.logger.info("{}已切换为主节点".format(ip))

    def unbind_vip(self):
        vip = self.config.get_vip()
        unbind_cmd = "/sbin/ip addr del {}/24 dev eth0".format(vip)
        self.__exec_cmd(unbind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def bind_vip(self):
        vip = self.config.get_vip()
        bind_cmd = "/sbin/ip addr add {}/24 dev eth0".format(vip)
        self.__exec_cmd(bind_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def redis_master(self):
        # 转变为standby
        cmd = self.__redis_cli + self.command + 'NO ONE'
        (status, output) = commands.getstatusoutput(cmd)
        if status == 0:
            self.logger.info('slaveof no one success')
        else:
            self.logger.error('slaveof no one fail')

    def redis_check(self, peer_check=False):
        cmd = self.__redis_cli + 'PING'
        if peer_check == True:
            cmd = "ssh root@{} '{}'".format(self.config.get_peer_ip(), cmd)
        result = commands.getoutput(cmd)
        if len(result.split('\n')) > 1:
            result = result.split('\n')[-1]
        print result.strip()
        if result.strip() == 'PONG':
            return True
        else:
            return False

    def redis_backup(self):
        cmd = self.__redis_cli + self.command + self.config.get_peer_ip() + ' ' + self.config.node.get_port()
        code, output = commands.getstatusoutput(cmd)
        if code == 0:
            self.logger.info("slaveof peer success")
        else:
            self.logger.info("slaveof peer fail")


if __name__ == '__main__':
    check = Check()
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if len(sys.argv) > 2:
            argument = sys.argv[2]

        if command == "check_state_file":
            check.check_state_file()

        elif command == "write_state_file":
            check.operation.change_ip_to_master(argument)

        elif command == "check_monitor":
            check.check_monitor()
