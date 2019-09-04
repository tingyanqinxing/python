from web.commonTools.tools import *

##判断输入的域名是否能用
###in: postData,type=dict
###return : (True，domainList) | (False,descInfo)
def cloudflareFrontPostDataIsValid(postData):
    if postData["domains"] == "请输入域名，每行一个":
        return False,"请输入域名，每行一个"
    else:
        domains = postData["domains"].split("\r\n")
        domains = [d.strip() for d in domains]
        for d in domains:
            res = checkMainDomainIsValid(d)
            print("check domain %s result: %s" %(d,res))
            if not res:
                return False,"%s is not valid,pls check" %(d)
        return True,domains
