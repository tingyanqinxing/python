import requests,json
from web.commonTools.cloudflareApiUrl import *

class CloudflareClient():
    def __init__(self,authEmail,authKey):
        self._authEmail = authEmail
        self._authKey = authKey
        self._requestHeaders = {"Content-Type":"application/json",
                                "X-Auth-Email": self._authEmail,
                                "X-Auth-Key": self._authKey
                               }

    def getZoneID(self):
        res = requests.get(getZoneIDUrl, headers=self._requestHeaders).json()
        try:
            self.zoneID = res['result'][0]['id']
        except IndexError:
            self.zoneID = None
        return self.zoneID

    def getUserID(self):
        res = requests.get(getUserIDUrl, headers=self._requestHeaders).json()
        try:
            self.userID = res['result']['id']
        except IndexError:
            self.userID = None
        return self.userID

    def getAccountID(self):
        res = requests.get(getAccountIDUrl,headers=self._requestHeaders).json()
        try:
            self.accountID = res['result'][1]["id"]
        except IndexError:
            self.accountID = None
        return self.accountID

    def getDomainZoneID(self,domain):
        requestParams = {"name":domain}
        res = requests.get(getZoneIDUrl,headers=self._requestHeaders,params=requestParams).json()
        try:
            self.domainZoneID = res['result'][0]['id']
        except IndexError:
            self.domainZoneID = None
        return self.domainZoneID

    def addDomain(self,accountid,domain):
        requestParams = {"name":domain,"account":{"id":accountid},"jump_start":False,"type":"full"}
        res = requests.post(getZoneIDUrl,data=json.dumps(requestParams),headers=self._requestHeaders).json()
        print("addDomain %s result is: %s" %(domain,res))
        resCode = res["success"]
        if resCode:
            return True,"添加成功"
        else:
            return False,str(res["errors"])
    ####return (True,[("type=A|CNAME","name='api.0j8uymf.com'",proxyed=True|False,"domainRecordID=11ae53"),...])|(False,["errors"])
    def listDomainRecords(self,domainZoneID,domain):
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("listDomainRecord of domain %s result is : %s" %(domain,res))
        resCode = res["success"]
        if resCode:
            if res["result"]:
                result = res["result"]
                retList = []
                for l in result:
                    retList.append((l['id'],l['type'],l["name"],l['content'],l['proxied']))

                return True,retList
            else:
                return True,["无解析记录"]
        else:
            return False,res["errors"]
    def delDomainRecord(self,domain,domainZoneID,domainRecordID):
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records/" + domainRecordID
        res = requests.delete(url,headers=self._requestHeaders).json()
        print("deleteRecord for domain: %s result is %s" %(domain,res))
        resCode = res["success"]
        if resCode:
            return True,"删除成功"
        else:
            return False,str(res["errors"])

    def addDomainRecord(self,domain,domainZoneID,type,name,content,proxied):
        requestParams = {"type":type,"name":name,"content":content,"ttl":1,"priority":10,"proxied":proxied}
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records"
        res = requests.post(url,data=json.dumps(requestParams),headers=self._requestHeaders).json()
        print("addDomainRecord %s result is: %s" %(domain,res))
        resCode = res["success"]
        if resCode:
            return True,"添加成功"
        else:
            return False,str(res["errors"])

    ###return (True,[{"ruleName":"RuleContent"},...]) | (False,"errors")
    def getDomainRateLimits(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/rate_limits"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("getDomainRateLimits for domain %s result is: %s" %(domain,res))
        resCode = res["success"]
        if resCode:
            result = res["result"]
            if result:
                ruleList = []
                for r in result:
                    ruleName = r["description"]
                    ruleContent = "methods : %s | schemes : %s | urls : %s  period : %s threshold : %s --> action : %s timeout : %s --> disabled : %s" %(r["match"]['request']["methods"],r["match"]['request']["schemes"],r["match"]['request']['url'],str(r["period"]),str(r["threshold"]),r["action"]["mode"],str(r["action"]["timeout"]),str(r["disabled"]))
                    ruleList.append({ruleName:ruleContent})
                return True,ruleList
            else:
                return False,"没有RateLimit规则"
        else:
            return False,str(res["errors"])

    def addDomainRateLimits(self,domain,domainZoneID,disabled,description,methods,schemes,aurl,threshold,period,action_mode,action_timeout,resp_body):
        url = getZoneIDUrl + "/" + domainZoneID + "/rate_limits"
        requestParams = {
            "disabled" : disabled,
            "description":description,
            "match": {
                "request": {
                    #"methods": ["GET", "POST"],
                    #"schemes": ["HTTP", "HTTPS"],
                    "methods": methods,
                    "schemes": schemes,
                    "url": aurl
                },
                "response": {},
                "headers": [{
                    "name": "Cf-Cache-Status",
                    "op": "ne",
                    "value": "HIT"
                }]
            },
            "threshold":threshold,
            "period":period,
            "action": {
                "mode": action_mode,
                "timeout": action_timeout,
                "response": {
                    "content_type": "text/xml",
                    #"body": resp_body
                }
            }
        }
        print("url: %s" %url)
        print("requestParams:%s" %(requestParams))
        res = requests.post(url,data=json.dumps(requestParams),headers=self._requestHeaders).json()
        print("addDomainRateLimits for domain %s result is: %s" % (domain, res))
        resCode = res["success"]
        if resCode:
            return True,"添加成功"
        else:
            return False,str(res["errors"])



