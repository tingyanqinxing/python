from django.urls import path
from web import views

app_name="web"
urlpatterns = [
    path('',views.index,name="index"),
    path('testConnect/',views.testNginxConnect,name="testNginxConnect"),
    path('changeNginxConfig',views.changeNginxConfig,name="changeNginxConfig"),
    path('nginx_301',views.nginx301,name="nginx301"),
    path('cloudflare_operate',views.cloudflare_operate,name="cloudflare_operate"),
]