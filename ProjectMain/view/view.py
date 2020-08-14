from django.http import HttpResponse,JsonResponse
from django.shortcuts import render
import json
import threading
from ProjectMain.RealTimeMonitoring.utils import Util

# mydb=connect(
#     host='localhost',
#     user='root',
#     passwd='123456',
#     database='DgaMonitoring'
# )

#coding:utf-8
# 主页面
def main(request):
    context={}
    context['hello']='hello'
    return render(request,'main.html',context)
# 我的主页
def Index(request):
    return render(request,'Index.html')
def Welcome(request):
    return render(request,'welcome.html')
# 待开发
def more(request):
    return render(request,'more.html')

