from web.commonTools.tools import *
from django.shortcuts import render


###装饰器，检查前端参数
def cfFrontPostBaseDataCheck(fun):
    def wrapper(request):
        print("in %s" %(fun.__name__))
        postData = request.POST
        print(postData)
        templateData = {
            "tipMessage": [],
            "formProcessUrl": "cloudflareAddDomain",

        }
        if not postData:
            templateData["tipMessage"] = ["请输入域名，每行一个"]
            return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
        if postData["domains"] == "请输入域名，每行一个":
            templateData["tipMessage"] = ["请输入域名，每行一个"]
            return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
        domains = postData["domains"].split("\r\n")
        domains = [d.strip() for d in domains]
        for d in domains:
            res = checkMainDomainIsValid(d)
            print("check domain %s result: %s" %(d,res))
            if not res:
                templateData["tipMessage"] = ["%s is not valid,pls check" %(d)]
                return render(request, "web/cloudflare/cloudflareListBase.html", templateData)
        return fun(request)
    return wrapper


