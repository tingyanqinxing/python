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

@cfFrontPostBaseDataCheck("web/cloudflare/cloudflareListBase.html","cloudflareAddDomain")
def cloudflareAddDomain(request):
    postData = request.POST
    templateData = {
                    "tipMessage":[],
                    "formProcessUrl":"cloudflareAddDomain",
                    "tableHead" : ("序号","域名","结果","其他信息"),
                    "tableBody": []
                    }

    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail,authKey)
    ###多个账号得情况下，需确认具体得账号
    cf_accountID = cloudflareClient.getAccountID()
    t = 0
    for d in domains:
        res = cloudflareClient.addDomain(cf_accountID,d)
        templateData["tableBody"].append((str(t), d,str(res["success"]), res["errors"]))

    return render(request,"web/cloudflare/cloudflareListBase.html",templateData)

@cfFrontPostBaseDataCheck("web/cloudflare/cloudflareListBase.html","cloudflareListDomainRecord")
def cloudflareListDomainRecord(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareListDomainRecord",
                    "tableHead" : ("序号","域名","类型","子域名",
                                   "值","CDN加速","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail,authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        print("ZoneID of domain %s is %s" %(d,domainZoneID))
        if not domainZoneID:
            templateData["tableBody"].append((t,d,'-','-','-','-','域名不存在'))
            continue
        res = cloudflareClient.listDomainRecords(domainZoneID,d)
        if res["success"]:
            r = res["result"]
            if r:
                r = res["result"][0]
                templateData["tableBody"].append((t, d, r["type"],
                                              r["name"],
                                              r['content'],
                                               str(r["proxied"]),
                                              '-'))
            else:
                templateData["tableBody"].append((t, d, "-",
                                                  '-',
                                                  '-',
                                                  '-',
                                                  '无解析记录'))
        else:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', res["errors"]))
    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

@cfFrontPostBaseDataCheck("web/cloudflare/cloudflareDeleteDomainRecord.html","cloudflareDeleteDomainRecord")
def cloudflareDeleteDomainRecord(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "tableHead": ("序号", "域名", "类型", "子域名",
                                  "值", "CDN加速", "其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail,authKey)
    deleType = postData['deleteType']
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', '域名不存在'))
            continue
        print("ZoneID of domain %s is %s" % (d, domainZoneID))
        res = cloudflareClient.listDomainRecords(domainZoneID, d)
        ####获取域名recordID,根据recordid删除记录
        if res["success"]:
            if res["result"]:
                for r in res["result"]:
                    if r["type"] == deleType:
                        recordID = r["id"]
                        res = cloudflareClient.delDomainRecord(d, domainZoneID, recordID)
                        if res["success"]:
                            templateData["tableBody"].append((t, d, '-', '-', '-', '-', "删除成功"))
                        else:
                            templateData["tableBody"].append((t, d, '-', '-', '-', '-', res["errors"]))
            else:
                templateData["tableBody"].append((t, d, '-', '-', '-', '-', "无记录"))
        else:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', res["errors"]))
    return render(request, "web/cloudflare/cloudflareDeleteDomainRecord.html", templateData)

@cfFrontPostBaseDataCheck("web/cloudflare/cloudflareAddDomainRecord.html",'cloudflareAddDomainRecord')
def cloudflareAddDomainRecord(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "tableHead": ("序号", "域名", "类型", "子域名",
                                  "值", "CDN加速", "其他信息"),
                    "tableBody": []
                    }

    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
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
        t = 0
        for d in domains:
            t+=1
            domainZoneID = cloudflareClient.getDomainZoneID(d)
            if not domainZoneID:
                templateData["tableBody"].append((t, d, '-', '-', '-', '-', '域名不存在'))
                continue
            res = cloudflareClient.addDomainRecord(d,domainZoneID,addType,recordName,recordValue,bool(proxyed))
            if res['success']:
                r = res["result"]
                templateData["tableBody"].append((t, d, r["type"],
                                                  r["name"],
                                                  r['content'],
                                                  str(r["proxied"]),
                                                  '-'))
            else:
                templateData["tableBody"].append((t, d, '-', '-', '-', '-', res["errors"]))
        return render(request, "web/cloudflare/cloudflareAddDomainRecord.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareListDomainRateLimits')
def cloudflareListDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareListDomainRateLimits",
                    "tableHead": ("序号", "域名", "名称", "url",
                                  "阈值", "周期", "动作","生效时长","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail, authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', '-', '-', '域名不存在'))
            continue
        res = cloudflareClient.getDomainRateLimits(d,domainZoneID)
        if res["success"]:
            if res['result']:
                r = res['result'][0]
                templateData["tableBody"].append((t, d, r['description'], r['match']['request']['url'], r['threshold'], r['period'],r['action']['mode'],
                                              r['action']['timeout'], '-'))
            else:
                templateData["tableBody"].append((t, d, '-', '-', '-', '-', '-', '-', '无记录'))
        else:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', '-', '-', str(res['errors'])))

    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareAddDomainRateLimits.html','cloudflareAddDomainRateLimits')
def cloudflareAddDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "tableHead": ("序号", "域名", "名称", "url",
                                  "阈值", "周期", "动作","生效时长","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
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
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-','-', '-', '域名不存在'))
            continue
        res = cloudflareClient.addDomainRateLimits(d,domainZoneID,isDisabled,description,methods,schemes,url,threshold,period,action_mode,action_timeout,resp_body)
        if res["success"]:
            r = res['result']
            templateData["tableBody"].append((t, d, r['description'], r['match']['request']['url'], r['threshold'], r['period'],r['action']['mode'],
                                              r['action']['timeout'], '-'))
        else:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', '-', '-', str(res['errors'])))
    return render(request, "web/cloudflare/cloudflareAddDomainRateLimits.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareGetDomainNameServer')
def cloudflareGetDomainNameServer(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareGetDomainNameServer",
                    "tableHead": ("序号", "域名", '域名服务器','DNS','域名状态',"状态码", "状态说明",'注册商','联系邮箱','创建时间','过期时间'),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]

    t = 0
    for d in domains:
        t += 1
        res = getDomainNameServer(d)
        if res['StateCode'] == 1:
            r = res["Result"]
            templateData["tableBody"].append((t,d,r['WhoisServer'],r['DnsServer'],r['DomainStatus'],res['StateCode'],res['Reason'],r['Registrar'],
                                              r['Email'],r['CreationDate'],r['ExpirationDate']))
        else:
            templateData["tableBody"].append((t,d,'-','-','-',res['StateCode'],res['Reason'],'-','-','-','-'))
    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)



def SIMS_show(request):
    return HttpResponse("ok")

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareDeleteDomainRateLimits')
def cloudflareDeleteDomainRateLimits(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareDeleteDomainRateLimits",
                    "tableHead": ("序号", "域名", "结果","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail, authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '域名不存在'))
            continue
        else:
            res = cloudflareClient.getDomainRateLimits(d,domainZoneID)
            templateData["tableBody"].append((t, d, str(res['success']),str(res["errors"])))
    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareListDomainWAFRules')
def cloudflareListDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl":"cloudflareListDomainWAFRules",
                     "tableHead": ("序号", "域名", "名称","expression","action","paused","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail, authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-','域名不存在'))
            continue
        else:
            res = cloudflareClient.getFirewallRules(d,domainZoneID)
            if res["success"]:
                if res["result"]:
                    r = res["result"][0]
                    templateData["tableBody"].append((t,d,r["description"],r['filter']['expression'],r['action'],r['paused'],'-'))
                else:
                    templateData["tableBody"].append(
                        (t, d, '-', '-', '-', '-', '无记录'))
            else:
                templateData["tableBody"].append(
                    (t, d, '-', '-', '-', '-', str(res["errors"])))

    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareDeleteDomainWAFRules')
def cloudflareDeleteDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareDeleteDomainWAFRules",
                    "tableHead": ("序号", "域名", "结果", "其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail, authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t,d,'-','域名不存在'))
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
                        templateData["tableBody"].append((t, d, res["success"], '-'))
                ####没有rules
                else:
                    templateData["tableBody"].append((t, d, res["success"], '没有WAF规则'))
            else:
                ###获取FirewallRules失败
                templateData["tableBody"].append((t, d, res["success"], str(res['errors'])))
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

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareAddDomainWAFRules.html','cloudflareAddDomainWAFRules')
def cloudflareAddDomainWAFRules(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "tableHead": ("序号", "域名", "名称","expression","action","paused","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
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
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '-', '-', '-', '-', '域名不存在'))
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
                    r = res['result'][0]
                    templateData["tableBody"].append(
                        (t, d, r["description"], r['filter']['expression'], r['action'], r['paused'], '-'))
                else:
                    templateData["tableBody"].append(
                        (t, d, '-', '-', '-', '-', str(res["errors"])))
            else:
                print("add filter failed")
                templateData["tableBody"].append(
                    (t, d, '-', '-', '-', '-', str(res["errors"])))
    print(templateData)
    return render(request, "web/cloudflare/cloudflareAddDomainWAFRules.html", templateData)

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareFlushDomainCache')
def cloudflareFlushDomainCache(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl":"cloudflareFlushDomainCache",
                    "domains": '请输入域名，每行一个',
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
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

@cfFrontPostBaseDataCheck('web/cloudflare/cloudflareListBase.html','cloudflareSetDomainAlwaysUseHTTPS')
def cloudflareSetDomainAlwaysUseHTTPS(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareSetDomainAlwaysUseHTTPS",
                    "tableHead": ("序号", "域名","其他信息"),
                    "tableBody": []
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
    cloudflareClient = CloudflareClient(authEmail, authKey)
    t = 0
    for d in domains:
        t += 1
        domainZoneID = cloudflareClient.getDomainZoneID(d)
        if not domainZoneID:
            templateData["tableBody"].append((t, d, '域名不存在'))
            continue
        else:
            res = cloudflareClient.setDomainAlwaysUseHttps(d,domainZoneID)
            if res["success"]:
                templateData["tableBody"].append((t,d,"设置成功"))
            else:
                templateData["tableBody"].append((t, d, str(res['errors'])))
    return render(request, "web/cloudflare/cloudflareListBase.html", templateData)

@cfFrontPostBaseDataCheck("web/cloudflare/cloudflareListBase.html",'cloudflareCreateDomainCertificate')
def cloudflareCreateDomainCertificate(request):
    postData = request.POST
    print(postData)
    templateData = {"tipMessage": [],
                    "formProcessUrl": "cloudflareCreateDomainCertificate",
                    "domains": '请输入域名，每行一个',
                    }
    domains = postData["domains"].split("\r\n")
    domains = [d.strip() for d in domains]
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

