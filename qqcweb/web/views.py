from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
from web.commonTools.tools import *
from web.commonTools.cloudflareClient import *
import logging
logger = logging.getLogger("django")

def index(request):
    return render(request,'web/index.html')

def nginx301(request):
    return render(request,"web/nginx/nginx_301.html",{"formSubmitButtonName": "testNginxConnect","postUrlName": "testNginxConnect"})

def testNginxConnect(request):
    logger.info("request POST: %s" % (str(request.POST)))
    postData = request.POST
    indexTemplateData = {"tipMessage": "",
                         "HostIP": postData["HostIP"],
                         "HostPort": postData["HostPort"],
                         "LoginUser": postData["LoginUser"],
                         "LoginPwd": postData["LoginPwd"],
                         "RootPwd": postData["RootPwd"],
                         "nginxConfigContext": None,
                         ###readonly:配置文件是否可写
                         "readonly": 1,
                         "formSubmitButtonName": "TestConnect",
                         "postUrlName": "testConnect",
                         ###是否可增加新配置文件
                         "addConfigIsAvailable":False
                         }
    if not checkIP(postData["HostIP"]):
        indexTemplateData["tipMessage"] = "IP Address is not valid"
    elif not checkPortIsValid(postData["HostPort"]):
        indexTemplateData["tipMessage"] = "IP Port is not valid"
    else:
        remoteConnect = NginxConfProcessor(postData["HostIP"], postData["HostPort"], postData["LoginUser"],postData["LoginPwd"], postData["RootPwd"], postData["NginxInstallPath"])
        if not remoteConnect.ssh:
            indexTemplateData["tipMessage"] = remoteConnect.connectErrorInfo
        else:
            logger.info("connect to server successfilly")
            retVal = remoteConnect.parser()
            ###分析nginx配置文件返回真，说明nginx配置文件读取成功
            if retVal:
                indexTemplateData["nginxConfigContext"] = remoteConnect.nginxConfigContentDict
                indexTemplateData["formSubmitButtonName"] = "Change Config"
                indexTemplateData["postUrlName"] = "changeNginxConfig"
                indexTemplateData["addConfigIsAvailable"] = True
            ###分析nginx配置文件返回不为真，说明nginx配置文件读取失败
            else:
                indexTemplateData["tipMessage"] = "Error: " + remoteConnect.connectErrorInfo
    return render(request, "web/nginx/nginx_301.html", indexTemplateData)

def changeNginxConfig(request):
    logger.info("request POST: %s" % (str(request.POST)))
    postData = request.POST
    print(postData)
    for key in postData:
        if key in ("HostIP","HostPort","LoginUser","LoginPwd","RootPwd",'NginxInstallPath',"csrfmiddlewaretoken","main"):
            continue
        else:
            remoteConnect = NginxConfProcessor(postData["HostIP"], postData["HostPort"], postData["LoginUser"],postData["LoginPwd"], postData["RootPwd"], postData["NginxInstallPath"])
            remoteConnect.parser()
            ret = remoteConnect.config(key, postData[key])
            if ret:
                respRet = True
                continue
            else:
                respRet = False
                break
    if respRet:
        return HttpResponse("Configure Successfully")
    else:
        return HttpResponse("Configure Failure")

def cloudflare_operate(request):
    print(request.POST)
    postData = request.POST
    templateData = {"tipMessage":'',
                    "domains":'请输入域名，每行一个',
                    }
    ###post数据为空
    if not postData:
        templateData["tipMessage"] = "请输入域名，每行一个"
    ##未输入数据
    elif postData["domains"] == "请输入域名，每行一个":
        templateData["tipMessage"] = "请输入域名，每行一个"
    ###有数据
    else:
        print(postData["domains"])
        # print(type(postData["domains"])) = str
        ##type(domains) = list
        domains = postData["domains"].split("\r\n")

        ##type: str
        ###recordType: A|CNAME|TXT
        recordType = postData["recordType"]
        recordValue = postData["recordValue"]
        ###operateType : ListRecord|AddDomain|AddRecord
        operateType = postData["operateType"]

        ###检查主域名是否合法,有不合法域名立即返回
        for d in domains:
            res = checkMainDomainIsValid(d)
            print("check domain %s result: %s" %(d,res))
            if not res:
                templateData["tipMessage"] = "%s is not valid,pls check" %(d)
                return render(request, "web/cloudflare/cloudflareListBase.html", templateData)


        cloudflareClient = CloudflareClient("helaowang@gmail.com","799bdf658832da5b74be6c0a4a2b35d3a43e3")
        cf_zoneID = cloudflareClient.getZoneID()
        cf_userID = cloudflareClient.getUserID()
        ###多个账号得情况下，需确认具体得账号
        cf_account = cloudflareClient.getAccountID()

        ###列出记录
        if operateType == "ListRecord":
            for d in domains:
                ##获取domainZoneID
                domainZoneID = cloudflareClient.getDomainZoneID(d)
                print("domainZoneID=%s" %domainZoneID)
                ##获取记录
                domainRecordList = cloudflareClient.getDomainRecordList(domainZoneID)
                print("domainRecordList for domain %s : %s" %(d,domainRecordList))
        elif operateType == "AddDomain":
            pass
        elif operateType == "AddRecord":
            pass
        else:
            pass
        templateData["tipMessage"] = "ok"
    return render(request,"web/cloudflare/cloudflareListBase.html",templateData)
