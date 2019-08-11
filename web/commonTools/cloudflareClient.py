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

    def getDomainRecordList(self,domainZoneID):
        #requestParams = {"name":domain}
        url = getZoneIDUrl + "/" + domainZoneID + "/dns_records"
        res = requests.get(url,headers=self._requestHeaders).json()
        print(res)
