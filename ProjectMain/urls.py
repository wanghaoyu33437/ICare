"""DGA URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from ProjectMain.view import view,uploadView,DGAURLview,AvlView

# router = routers.DefaultRouter()
# router.register(r'users', views.UserViewSet)
# router.register(r'groups', views.GroupViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    # url(r'^',include((router.urls))),
    # url(r'^api-auth/',include('rest_framework.urls',namespace='rest_framework')),
    url(r'^$',view.main),
    path('Index/',view.Index),
    path('Welcome/',view.Welcome),
#DGA or URL
    path('DGArequest/',DGAURLview.DGArequest),
    path('DGAresponse/',DGAURLview.DGAresponse),
    path('DGAquery/',DGAURLview.DGAquery),
    path('DGAstop/',DGAURLview.DGAstop),
    path('DGAstart/',DGAURLview.DGAstart),
    path('DGAdel/', DGAURLview.DGAdel),
    path('URLrequest/',DGAURLview.URLrequest),
    path('URLquery/',DGAURLview.URLquery),
    path('URLstart/',DGAURLview.URLstart),
    path('URLstop/', DGAURLview.URLstop),
    path('URLdel/', DGAURLview.URLdel),
# 文件上传
    path('UploadPar/', uploadView.UploadPar),
    path('Upload/', uploadView.Upload),
    path('FileUpload/', uploadView.FileUpload),
# 数据分析
    path('BasedataPar/', uploadView.BasedataPar),
    path('Basedata/', uploadView.Basedata),
    path('Datashow/',uploadView.Datashow),
# 流量分析
    path('FlowAnalyzer/',uploadView.FlowAnalyzer),
    path('FlowAnalyzerPar/',uploadView.FlowAnalyzerPar),
# 协议分析
    path('ProtoAnalyzer/', uploadView.ProtoAnalyzer),
    path('ProtoAnalyzerPar/', uploadView.ProtoAnalyzerPar),
# IP地图
    path('IpMap/', uploadView.IpMap),
    path('IpMapPar/', uploadView.IpMapPar),
# 异常警告
    path('ExceptWaringPar/',uploadView.ExceptWaringPar),
    path('ExceptWaring/',uploadView.ExceptWaring),
# web数据提取
    path('WebData/',uploadView.WebData),
    path('WebDataPar/',uploadView.WebDataPar),
# ftp数据提取
    path('FtpData/',uploadView.FtpData),
    path('FtpDataPar/',uploadView.FtpDataPar),
# telnet数据提取
    path('TelnetData/',uploadView.TelnetData),
    path('TelnetDataPar/',uploadView.TelnetDataPar),
# 敏感数据提取
    path('SenData/',uploadView.SenData),
    path('SenDataPar/',uploadView.SenDataPar),
# AVL病毒检索
    path("AVLSelectFilePar/",AvlView.AVLSelectFilePar),
    path("AVLSelectFile/",AvlView.AVLSelectFile),
    path("AVLScannerFiles/", AvlView.AVLScannerFiles),
    path("AVLSelectFile/ShowAVLResult/",AvlView.ShowAVLResult),
# 待开发
    path("more/",view.more)
]
