import os
import re

import paramiko
import logging
import random
import time
logger = logging.getLogger("django")
##检查ip地址是否合法
def checkIP(ip):
    import IPy
    try:
        IPy.IP(ip)
        return True
    except Exception:
        return False

###检查端口是否合法
def checkPortIsValid(port):
    try:
        if 1 <= int(port) <= 65535:
            return True
        else:
            return False
    except:
        return False

###检查域名是否合法,必须为主域名
def checkMainDomainIsValid(domain):
    pattern = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62}$')
    return True if pattern.match(domain) else False




###nginx配置文件分析类
class NginxConfProcessor:
    def __init__(self,hostip,port,loginUser,loginPwd,rootPwd,nginxInstallPath="/usr/local/gacp/nginx/"):
        self.host = hostip
        self.port = port
        self.loginUser = loginUser
        self.loginPwd = loginPwd
        self.ngxInstallPath = nginxInstallPath
        self.rootPwd = rootPwd
        ###nginxConfigContentDict : {"File":"ContentList",...}
        ###存储nginx配置内容，格式 文件名：内容list
        self.nginxConfigContentDict = {}
        ###self._includePathList : include包含的所有文件的决对路径
        self._includePathList = []
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(hostip,port,loginUser,loginPwd)
            self.sftpClient = self.ssh.open_sftp()
            self.connectErrorInfo = "Create SSH Client and SFTP Client successfully"
        except TimeoutError:
            self.connectErrorInfo = "Connect Timeout"
            self.ssh = None
        except paramiko.ssh_exception.AuthenticationException:
            self.connectErrorInfo = "Authentication failed"
            self.ssh = None
        except:
            self.connectErrorInfo = "Uncatched error, please checked"
            self.ssh = None

    def parser(self):
        ###开始分析配置
        if not self.__isRemotePathExisted(self.ngxInstallPath):
            self.connectErrorInfo = "Nginx Install Path Error"
            return False
        else:
            ##读取主配置文件
            with self.sftpClient.open(os.path.join(self.ngxInstallPath,"conf/nginx.conf"),"r") as file:
                nginxTempConfig = file.readlines()
                nginxFilterdConfig = self._formatConfig(nginxTempConfig)
                self.nginxConfigContentDict["main"] = nginxFilterdConfig
                logger.info("nginxConfigContentDirc = %s" %(str(self.nginxConfigContentDict)))
            while self._includePathList:
                for i in self._includePathList:
                    fileName = os.path.basename(i)
                    if fileName == "mime.types":
                        continue
                    with self.sftpClient.open(i.strip(),'r') as file:
                        nginxTempConfig = file.readlines()
                        nginxFilterdConfig = self._formatConfig(nginxTempConfig)
                        self.nginxConfigContentDict[fileName] = nginxFilterdConfig

                self.connectErrorInfo = "Read Nginx Config Successfully"
                return True
    ###格式化配置文件 in: 配置文件readlines列表 out: (格式化后的config list),include的文件名(绝对路径)写入self._includePathList
    def _formatConfig(self,configList):
        nginxFilterdConfig = []
        for line in configList:
            if line.strip() and not line.strip().startswith('#'):
                nginxFilterdConfig.append(line)
            ###读取include的配置路径
            if line.strip().startswith("include"):
                file = line.strip().split("include")[1].strip().strip(";")
                ###include的路径中不包含*
                if file.find("*") == -1:
                    ##incldude的路径是个绝对路径
                    if os.path.isabs(file):
                        self._includePathList.append(file)
                    else:
                        self._includePathList.append(os.path.join(os.path.join(self.ngxInstallPath,"conf/"),file))
                ##include的路径中包含*
                else:
                    ##incldude的路径是个绝对路径
                    if os.path.isabs(file):
                        command = "ls " + file
                        ret,retContent = self._execRemoteCmd(command)
                        if ret:
                            for i in retContent:
                                self._includePathList.append(i)
                    else:
                        command = "ls " + os.path.join(os.path.join(self.ngxInstallPath,'conf/'),file)
                        ret, retContent = self._execRemoteCmd(command)
                        if ret:
                            for i in retContent:
                                self._includePathList.append(i)
        return nginxFilterdConfig

    ##远程服务器目录或文件是否存在
    def __isRemotePathExisted(self,path):
        command = "ls " + path
        remoteCmdResult, remoteCmdResultContent = self._execRemoteCmd(command)
        if remoteCmdResult:
            return True
        else:
            return False

    def _execRemoteCmd(self,cmd):
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        stderr = stderr.readlines()
        stdout = stdout.readlines()
        if stderr:
            return False,stderr
        else:
            return True,stdout

    def reconnect(self):
        self.ssh.connect(self.host,self.port, self.loginUser, self.loginPwd)
        self.sftpClient = self.ssh.open_sftp()

    ##写nginx配置文件内容  in: 配置文件名,配置文件内容
    def config(self,fileName,contentList):
        # print(self._includePathList)
        # print(fileName)

        for p in self._includePathList:
            if os.path.basename(p).strip() == fileName.strip():
                filePath = p.strip()
                tempFile = "".join(random.sample([chr(i) for i in range(65, 91)],20))
                print("临时配置文件名称:%s" %tempFile)
                ###写入本地文件，上传到/tmp目录
                with open(tempFile,'w') as file:
                    file.writelines(contentList)
                self.sftpClient.put(tempFile,os.path.join("/tmp/",tempFile))
                print("上传配置文件%s结束" %tempFile)
                os.remove(tempFile)
                print("删除本地临时文件结束")
                print('su - root -c "\cp -f /tmp/%s %s"\n' %(tempFile,filePath))
                interact = self.ssh.invoke_shell()
                interact.send('su - root -c "\cp -f /tmp/%s %s"\n' %(tempFile,filePath))
                time.sleep(2)
                interact.send(self.rootPwd)
                out = interact.recv(65535)
                # stdin, stdout, stderr = self.ssh.exec_command('su - root -c "\cp -f /tmp/%s %s"' %(tempFile,filePath))

                # out = stdout.read()
                # error = stderr.read()
                print("标准正确输出:%s" %out)
                # print("标准错误输出:%s" %error)
                # if not error:
                #     print("拷贝配置文件成功")
                #     return True
                # else:
                #     print("拷贝配置文件失败，请检查")
                #     return False


                print("config end")
                return True


