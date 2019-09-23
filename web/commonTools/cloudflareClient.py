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
        return res


    ####return (True,[("type=A|CNAME","name='api.0j8uymf.com'",proxyed=True|False,"domainRecordID=11ae53"),...])|(False,["errors"])
    def listDomainRecords(self,domainZoneID,domain):
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("listDomainRecord of domain %s result is : %s" %(domain,res))
        return res


    def delDomainRecord(self,domain,domainZoneID,domainRecordID):
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records/" + domainRecordID
        res = requests.delete(url,headers=self._requestHeaders).json()
        print("deleteRecord for domain: %s result is %s" %(domain,res))
        return res

    def addDomainRecord(self,domain,domainZoneID,type,name,content,proxied):
        requestParams = {"type":type,"name":name,"content":content,"ttl":1,"priority":10,"proxied":proxied}
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records"
        res = requests.post(url,data=json.dumps(requestParams),headers=self._requestHeaders).json()
        print("addDomainRecord %s result is: %s" %(domain,res))
        return res

    ###return (True,[{"ruleName":"RuleContent"},...]) | (False,"errors")
    def getDomainRateLimits(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/rate_limits"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("getDomainRateLimits for domain %s result is: %s" %(domain,res))
        return res


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
        return res

    def delDomainRateLimits(self,domain,domainZoneID,domainRateLimitID):
        url = getZoneIDUrl + "/" + domainZoneID + "/rate_limits/" + domainRateLimitID
        res = requests.delete(url,headers=self._requestHeaders).json()
        print("delDomainRateLimits for domain %s result is : %s" %(domain,res))
        return res

    def getFirewallRules(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/firewall/rules"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("get Firewall Rules for domain %s result is : %s" %(domain,res))
        return res

    def deleteDomainFirewallRules(self,domain,domainZoneID,ruleID):
        url = getZoneIDUrl + "/" + domainZoneID + "/firewall/rules?id=" + ruleID
        res = requests.delete(url,headers=self._requestHeaders).json()
        print("Delete domain firewall rules for domain %s result is : %s " %(domain,res))
        return res

    def addDomainFirewallRules(self,domain,domainZoneID,filterID,action,description):
        url = getZoneIDUrl + "/" + domainZoneID + "/firewall/rules"
        requestParams = [{
            "filter": {
                "id": filterID
            },
            "action": action,
            "description": description
        }]
        res = requests.post(url, data=json.dumps(requestParams), headers=self._requestHeaders).json()
        print("add Domian Firewall Rules for domain %s result is : %s " % (domain, res))
        return res

    def getDomainFirewallFilters(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/filters"
        res = requests.get(url,headers=self._requestHeaders).json()
        print("get Domian Firewall Filters for domain %s result is : %s " %(domain,res))
        return res

    def deleteDomainFirewallFilters(self,domain,domainZoneID,filterID):
        url = getZoneIDUrl + "/" + domainZoneID + "/filters?id=" + filterID
        res = requests.delete(url, headers=self._requestHeaders).json()
        print("delete Domian Firewall Filters for domain %s result is : %s " % (domain, res))
        return res

    def addDomainFirewallFilters(self,domain,domainZoneID,expression):
        url = getZoneIDUrl + "/" + domainZoneID + "/filters"
        requestParams = [{
            "expression": expression
        }]
        res = requests.post(url, data=json.dumps(requestParams), headers=self._requestHeaders).json()
        print("add Domian Firewall Filters for domain %s result is : %s " % (domain, res))
        return res

    def deleteDomainCache(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/purge_cache"
        requestParams = {"purge_everything": True}
        res = requests.post(url,headers=self._requestHeaders,data=json.dumps(requestParams)).json()
        print("flush Domian Cache for domain %s result is : %s " % (domain, res))
        return res

    def setDomainAlwaysUseHttps(self,domain,domainZoneID):
        url = getZoneIDUrl + "/" + domainZoneID + "/settings/always_use_https"
        data = {"value": "on"}
        res = requests.patch(url,data=json.dumps(data),headers=self._requestHeaders).json()
        print("set domain always use https for domain %s result is : %s" %(domain,res))
        return res

    def createDomainCertificate(self,domain,):
        pass