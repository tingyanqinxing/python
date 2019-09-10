from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.
from web.commonTools.tools import *
from web.commonTools.cloudflareFrontValid import *
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

def cloudflareAddDomain(request):
    postData = request.POST
    print(postData)
    templateData = {
                    "tipMessage":[],
                    "formProcessUrl":"cloudflareAddDomain",
                    "domains":'请输入域名，每行一个',
                    }
    ###post数据为空
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode,info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request,"web/cloudflare/cloudflareListBase.html",templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail,authKey)
        ###多个账号得情况下，需确认具体得账号
        cf_accountID = cloudflareClient.getAccountID()
        ####添加域名到cloud flare
        for d in domains:
            res = cloudflareClient.addDomain(cf_accountID,d)
            if res["success"]:
                templateData["tipMessage"].append("%s :: %s" %(d,"添加成功"))
            else:
                templateData["tipMessage"].append("%s :: %s" % (d, str(res["errors"])))

    return render(request,"web/cloudflare/cloudflareListBase.html",templateData)

def cloudflareListDomainRecord(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareListDomainRecord",
                    "domains": '请输入域名，每行一个',
                    }
    ###post数据为空
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail,authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            print("ZoneID of domain %s is %s" %(d,domainZoneID))
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" %(d))
                continue
            res = cloudflareClient.listDomainRecords(domainZoneID,d)
            if res["success"]:
                results = res["result"]
                for r in results:
                    templateData["tipMessage"].append("%s ::: %s ::: %s ::: %s ::: proxied - %s" %(d,r["type"],r["name"],r["content"],r["proxied"]))
            else:
                templateData["tipMessage"].append("%s ::: %s" %(d,str(res["errors"])))

        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareDeleteDomainRecord(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "domains": '请输入域名，每行一个',
                    }
    ###post数据为空
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareDeleteDomainRecord.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareDeleteDomainRecord.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail,authKey)
        deleType = postData['deleteType']
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" %(d))
                continue
            print("ZoneID of domain %s is %s" % (d, domainZoneID))
            res = cloudflareClient.listDomainRecords(domainZoneID, d)
            ####获取域名recordID,根据recordid删除记录
            if res["success"]:
                for r in res["result"]:
                    if r["type"] == deleType:
                        recordID = r["id"]
                        res = cloudflareClient.delDomainRecord(d, domainZoneID, recordID)
                        if res["success"]:
                            templateData["tipMessage"].append("%s ::: %s" %(d,"删除成功"))
                        else:
                            templateData["tipMessage"].append("%s ::: %s" % (d, str(res["errors"])))
            else:
                templateData["tipMessage"].append("%s ::: %s" %(d,str(res["errors"])))
    if not templateData["tipMessage"]:
        templateData["tipMessage"].append("无匹配记录，未删除任何值")
    return render(request, "web/cloudflare/cloudflareDeleteDomainRecord.html", templateData)

def cloudflareAddDomainRecord(request):
    postData = request.POST
    print(postData)

    templateData = {"tipMessage": [],
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareAddDomainRecord.html", templateData)

    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareAddDomainRecord.html", templateData)
    else:
        domains = info
        addType = postData['addType']
        recordName = postData['recordName']
        recordValue = postData['recordValue']
        if postData['proxyed'] == "0":
            proxyed = False
        else:
            proxyed = True
        if not recordName or not recordValue:
            templateData["tipMessage"] = ["Name 或 Value不能为空"]
            return render(request, "web/cloudflare/cloudflareAddDomainRecord.html", templateData)
        else:
            cloudflareClient = CloudflareClient(authEmail,authKey)
            for d in domains:
                domainZoneID = cloudflareClient.getDomainZoneID(d)
                if not domainZoneID:
                    templateData["tipMessage"].append("domain %s not exists" %(d))
                    continue
                resCode,desc = cloudflareClient.addDomainRecord(d,domainZoneID,addType,recordName,recordValue,bool(proxyed))
                templateData["tipMessage"].append("add record for %s result: %s" %(d,desc))
            return render(request, "web/cloudflare/cloudflareAddDomainRecord.html", templateData)

def cloudflareListDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareListDomainRateLimits",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            res = cloudflareClient.getDomainRateLimits(d,domainZoneID)
            resCode = res["success"]
            if resCode:
                ###[{"ruleName":"RuleContent"},...])
                result = res["result"]
                if result:
                    ruleList = []
                    for r in result:
                        ruleName = r["description"]
                        ruleContent = "methods : %s | schemes : %s | urls : %s  period : %s threshold : %s --> action : %s timeout : %s --> disabled : %s" % (
                        r["match"]['request']["methods"], r["match"]['request']["schemes"],
                        r["match"]['request']['url'], str(r["period"]), str(r["threshold"]), r["action"]["mode"],
                        str(r["action"]["timeout"]), str(r["disabled"]))
                        ruleList.append({ruleName: ruleContent})
                    for r in ruleList:
                        key, = r
                        value, = r.values()
                        templateData["tipMessage"].append("%s ::: %s : %s" % (d, key, value))
                else:
                    templateData["tipMessage"].append("%s ::: %s" % (d, "没有RateLimit规则"))
            else:
                templateData["tipMessage"].append("%s ::: %s" %(d,str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareAddDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html",templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html", templateData)
    else:
        domains = info
        isDisabled = True if postData["disabled"] == "1" else False
        print(isDisabled)
        methodsP = postData["methods"]
        if methodsP == "GETandPOST":
            methods = ["GET", "POST"]
        elif methodsP == "GET":
            methods = ["GET"]
        elif methodsP == "POST":
            methods = ["POST"]
        elif methodsP == "ALL":
            methods = ["_ALL_"]
        schemeP = postData["scheme"]
        if schemeP == "HTTPSandHTTP":
            schemes = ["HTTP", "HTTPS"]
        elif schemeP == "HTTP":
            schemes = ["HTTP"]
        elif schemeP == "HTTPS":
            schemes = ["HTTPS"]
        elif schemeP == "ALL":
            schemes = ["_ALL_"]
        action_mode = postData["action"]
        try:
            description = postData["ruleName"]
            url = postData["url"]
            threshold = int(postData["threshold"])
            period = int(postData["period"])
            action_timeout = int(postData["timeout"])
        except:
            templateData["tipMessage"] = ["参数格式错误"]
            return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html", templateData)

        resp_body = "<error>This request has been rate-limited.</error>"

        if not description or not url or not threshold or not period or not action_timeout:
            templateData["tipMessage"] = ["缺少必须的参数，请检查"]
            return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html", templateData)

        cloudflareClient = CloudflareClient(authEmail, authKey)

        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            resCode , info = cloudflareClient.addDomainRateLimits(d,domainZoneID,isDisabled,description,methods,schemes,url,threshold,period,action_mode,action_timeout,resp_body)
            templateData["tipMessage"].append("add RateLimits for %s result: %s" % (d, info))
        return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html", templateData)

def cloudflareGetDomainNameServer(request):
    return HttpResponse("待开发")

def SIMS_show(request):
    return HttpResponse("ok")

def cloudflareDeleteDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareDeleteDomainRateLimits",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                res = cloudflareClient.getDomainRateLimits(d,domainZoneID)
                resCode = res["success"]
                if resCode:
                    result = res["result"]
                    if result:
                        for r in result:
                            ruleID = r["id"]
                            res = cloudflareClient.delDomainRateLimits(d,domainZoneID,ruleID)
                            resCode = res["success"]
                            if resCode:
                                templateData["tipMessage"].append("Del Domain RateLimit %s result is : %s" %(d, "删除RateLimit成功"))
                            else:
                                templateData["tipMessage"].append("Del Domain RateLimit %s result is : %s" %(d,str(res["errors"])))
                    else:
                        templateData["tipMessage"].append("Get Domain RateLimit %s result : %s" % (d, "没有RateLimit规则"))
                else:
                    templateData["tipMessage"].append("Get Domain RateLimit %s result : %s" %(d,str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareListDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl":"cloudflareListDomainWAFRules",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                res = cloudflareClient.getFirewallRules(d,domainZoneID)
                resCode = res["success"]
                if resCode:
                    result = res["result"]
                    if result:
                        for r in result:
                            templateData["tipMessage"].append("get domain Firewall Rules for doamin %s result is : %s" %(d,str(r)))
                    else:
                        templateData["tipMessage"].append("get domain Firewall Rules for doamin %s result is : %s" % (d, "没有Firewall Rules"))
                else:
                    templateData["tipMessage"].append("get domain Firewall Rules for doamin %s result is : %s" %(d,res["errors"]))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareDeleteDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareDeleteDomainWAFRules",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                ###获取ruleID
                res = cloudflareClient.getFirewallRules(d,domainZoneID)
                resCode = res["success"]
                ###获取ruleID,结果返回成功
                if resCode:
                    result = res["result"]
                    ###有rules,获取到ruld id,并删除rules
                    if result:
                        for r in result:
                            res = cloudflareClient.deleteDomainFirewallRules(d, domainZoneID, r["id"])
                            resCode = res["success"]
                            if resCode:
                                templateData["tipMessage"].append("delete domain Firewall Rules for doamin %s result is : %s" % (d, "删除成功"))
                            else:
                                templateData["tipMessage"].append("delete domain Firewall Rules for doamin %s result is : %s" % (d, str(res["errors"])))
                    ####没有rules
                    else:
                        templateData["tipMessage"].append("get domain Firewall Rules for doamin %s result is : %s" % (d, "没有Firewall Rules"))
                else:
                    ###获取FirewallRules失败
                    templateData["tipMessage"].append("get domain Firewall Rules for doamin %s result is : %s" % (d, str(res["errors"])))

                ####获取Domain包含的filter列表，并删除
                res = cloudflareClient.getDomainFirewallFilters(d,domainZoneID)
                resCode = res["success"]
                ###获取Domain包含的filter列表成功
                if resCode:
                    ####filters包含在res["result"]
                    result = res["result"]
                    ###result有内容，表示有filters，通过filterID删除filter
                    if result:
                        ####根据filterID删除filter
                        for r in result:
                            res = cloudflareClient.deleteDomainFirewallFilters(d,domainZoneID,r["id"])
                            if res["success"]:
                                print("delete firewall filter for domain %s result is : %s" %(d,"删除filter成功"))
                            else:
                                print("delete firewall filter for domain %s result is : %s" % (d, str(res["errors"])))
                    ###result为空，表示没有filters
                    else:
                        continue
                else:
                    print("get domain firewall filters for domain %s result is : %s" %(d,str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareAddDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareAddDomainWAFRules.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareAddDomainWAFRules.html", templateData)
    else:
        domains = info
        ruleName = postData["ruleName"]
        ruleExpression = postData["ruleExpression"]
        ruleAction = postData["action"]
        if ruleAction == "Block":
            action = "block"
        elif ruleAction == "JSChallenge":
            action = "js_challenge"
        elif ruleAction == "Allow":
            action = "allow"
        elif ruleAction == "Log":
            action = "log"

        if not ruleName or not ruleExpression:
            templateData["tipMessage"].append("参数不足，请检查")
            return render(request, "web/cloudflare/cloudflareAddDomainWAFRules.html", templateData)
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                ###先根据expression为domain添加filter
                res = cloudflareClient.addDomainFirewallFilters(d,domainZoneID,ruleExpression)
                ###添加filter成功,获取filterID,根据filterID新增rule
                if res["success"]:
                    filterID = res["result"][0]["id"]
                    res = cloudflareClient.addDomainFirewallRules(d,domainZoneID,filterID,action,ruleName)
                    ####添加firewall rules成功
                    if res["success"]:
                        templateData["tipMessage"].append("add Firewall Rules for domain %s result is %s" %(d,"rule添加成功"))
                    else:
                        templateData["tipMessage"].append("add Firewall Rules for domain %s result is %s" % (d, str(res["errors"])))
                else:
                    templateData["tipMessage"].append("add filter for domain %s result is : %s" % (d,str(res["errors"])))
                    continue
        return render(request, "web/cloudflare/cloudflareAddDomainWAFRules.html", templateData)

def cloudflareFlushDomainCache(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl":"cloudflareFlushDomainCache",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                res = cloudflareClient.deleteDomainCache(d,domainZoneID)
                if res["success"]:
                    templateData["tipMessage"].append("%s -- %s" %(d,"清除缓存成功"))
                else:
                    templateData["tipMessage"].append("%s -- %s" % (d, str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareSetDomainAlwaysUseHTTPS(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareSetDomainAlwaysUseHTTPS",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                res = cloudflareClient.setDomainAlwaysUseHttps(d,domainZoneID)
                if res["success"]:
                    templateData["tipMessage"].append("%s -- %s" % (d, "设置成功"))
                else:
                    templateData["tipMessage"].append("%s -- %s" % (d, str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

def cloudflareCreateDomainCertificate(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareCreateDomainCertificate",
                    "domains": '请输入域名，每行一个',
                    }
    if not postData:
        templateData["tipMessage"] = ["请输入域名，每行一个"]
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    ###检查前端数据是否合法
    resCode, info = cloudflareFrontPostDataIsValid(postData)
    if not resCode:
        templateData["tipMessage"].append(info)
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
    else:
        domains = info
        cloudflareClient = CloudflareClient(authEmail, authKey)
        for d in domains:
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tipMessage"].append("domain %s not exists" % (d))
                continue
            else:
                res = cloudflareClient.setDomainAlwaysUseHttps(d, domainZoneID)
                if res["success"]:
                    templateData["tipMessage"].append("%s -- %s" % (d, "设置成功"))
                else:
                    templateData["tipMessage"].append("%s -- %s" % (d, str(res["errors"])))
        return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

