from django.urls import path
from web import views

app_name="web"
urlpatterns = [
    path('',views.index,name="index"),
    path('testConnect/',views.testNginxConnect,name="testNginxConnect"),
    path('changeNginxConfig',views.changeNginxConfig,name="changeNginxConfig"),
    path('nginx_301',views.nginx301,name="nginx301"),
    path('cloudflareAddDomain',views.cloudflareAddDomain,name="cloudflareAddDomain"),
    path('cloudflareListDomainRecord',views.cloudflareListDomainRecord,name="cloudflareListDomainRecord"),
    path('cloudflareDeleteDomainRecord',views.cloudflareDeleteDomainRecord,name="cloudflareDeleteDomainRecord"),
    path('cloudflareAddDomainRecord',views.cloudflareAddDomainRecord,name="cloudflareAddDomainRecord"),
    path('cloudflareListDomainRateLimits',views.cloudflareListDomainRateLimits,name="cloudflareListDomainRateLimits"),
    path('cloudflareGetDomainNameServer',views.cloudflareGetDomainNameServer,name="cloudflareGetDomainNameServer"),
    path('cloudflareAddDomainRateLimits',views.cloudflareAddDomainRateLimits,name="cloudflareAddDomainRateLimits"),
    path('cloudflareListDomainWAFRules',views.cloudflareListDomainWAFRules,name="cloudflareListDomainWAFRules"),
    path('cloudflareAddDomainWAFRules',views.cloudflareAddDomainWAFRules,name="cloudflareAddDomainWAFRules"),
    path('SIMS_show',views.SIMS_show,name="SIMS_show"),
]