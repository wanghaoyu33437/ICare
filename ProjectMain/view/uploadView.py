# coding=utf-8

from django.http import HttpResponse,JsonResponse
from django.shortcuts import render
import json
import threading
from ProjectMain.utils.pcap_decode import PcapDecode
from django.views.decorators.http import require_http_methods
from ProjectMain.utils.pcap_filter import get_all_pcap,proto_filter,showdata_from_id
from ProjectMain.utils.flow_analyzer import time_flow, data_flow, get_host_ip, data_in_out_ip, proto_flow, most_flow_statistic
from ProjectMain.utils.proto_analyzer import common_proto_statistic, pcap_len_statistic, http_statistic, dns_statistic, most_proto_statistic
from ProjectMain.utils.ipmap_tools import get_geo,get_ipmap,getmyip
from ProjectMain.utils.data_extract import web_data, telnet_ftp_data, mail_data, sen_data, client_info
from ProjectMain.utils.except_info import exception_warning
from ProjectMain.Forms import UploadFileForm
from scapy.all import *
import os
import hashlib
# 全局变量
PCAP_NAME = ''  # 上传文件名
PD = PcapDecode()  # 解析器
PCAPS = None  # 数据包
UPLOAD_FILE_PATH='ProjectMain/Pcaps/' # 上传文件保存地址
# 上传界面显示
def UploadPar(request):
    return render(request,'DataAnalyzer/UploadPar.html')
def Upload(request):
    return render(request,'DataAnalyzer/Upload.html')

# 上传文件
@require_http_methods(['POST','GET'])
def FileUpload(request):
    if request.method=='GET':
        return render(request,'DataAnalyzer/Upload.html')
    else :
        pcap=request.FILES.get('file')
        # os.system('rm -rf'+UPLOAD_FILE_PATH+'*')
        if pcap.name.endswith('.pcap') or pcap.name.endswith('.cap'):
            with open(UPLOAD_FILE_PATH+pcap.name,'wb') as f :
                for chunk in pcap.chunks():
                    f.write(chunk)
            global  PCAP_NAME,PCAPS
            PCAP_NAME=pcap.name
            PCAPS=rdpcap(UPLOAD_FILE_PATH+pcap.name)
        return JsonResponse({'success':True})
    return JsonResponse({'success':False,'error':'上传数据包格式不正确...'})

'''
基本信息
'''
def BasedataPar(request):
    return render(request,"DataAnalyzer/basedataPar.html")
@require_http_methods(['POST','GET'])
def Basedata(request):
    '''
    基础数据解析
    :param request:
    :return:
    '''
    context = {}
    global PCAPS,PD
    # PCAPS = rdpcap('ProjectMain/Pcaps/ftp3.pcap')
    if PCAPS==None:
        context = dict()
        context['error']='请先上传要分析的数据包...'
        return render(request,"DataAnalyzer/basedata.html",context)
    else:
    # 将筛选的type和value通过表单获取
        params=request.POST
        if 'filter_type' in params:
            filter_type=params['filter_type']
            if 'value' in params:
                value=params['value']
                pcaps=proto_filter(filter_type,value,PCAPS,PD)
        else:
            # 默认显示全部协议
            pcaps=get_all_pcap(PCAPS,PD)
            pass
    context['pcaps'] = pcaps
    return render(request,"DataAnalyzer/basedata.html",context)
# 数据包具体显示
@require_http_methods(['GET'])
def Datashow(request):
    PDF_NAME=PCAP_NAME.split(".")[0]+".pdf"
    params=request.GET
    dataId=params["id"]
    dataId=int(dataId)-1
    data=showdata_from_id(PCAPS,dataId)
    return JsonResponse({"data":data})
# 流量分析
def FlowAnalyzerPar(request):
    return render(request,"DataAnalyzer/FlowAnalyzerPar.html")
def FlowAnalyzer(request):
    global PCAPS,PD
    # PCAPS = rdpcap('ProjectMain/Pcaps/ftp3.pcap')
    if PCAPS == None:
        context = dict()
        context['error']='请先上传要分析的数据包...'
        return render(request,"DataAnalyzer/FlowAnalyzer.html",context)
    else:
        print('******************')
        time_flow_dict = time_flow(PCAPS)               # 时间流量图
        host_ip = get_host_ip(PCAPS)                    # 获取抓包主机的IP
        data_flow_dict = data_flow(PCAPS, host_ip)      # 数据流入流出统计
        data_ip_dict = data_in_out_ip(PCAPS, host_ip)   # 访问IP地址统计
        proto_flow_dict = proto_flow(PCAPS)             # 常见协议流量统计
        most_flow_dict = most_flow_statistic(PCAPS, PD) # 流量最多协议数量统计
        most_flow_dict = sorted(most_flow_dict.items(), key=lambda d: d[1], reverse=True)
        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        pass
    context = dict()
    context['time_flow_keys']=list(time_flow_dict.keys())
    context['time_flow_values']=list(time_flow_dict.values())
    context['host_ip']=host_ip
    context['data_flow'] = data_flow_dict
    context['ip_flow'] = data_ip_dict
    context['proto_flow'] = list(proto_flow_dict.values())
    context['most_flow_key'] = most_flow_key
    context['most_flow_dict'] = most_flow_dict
    return render(request,'DataAnalyzer/FlowAnalyzer.html',context)


'''
协议分析
'''
def ProtoAnalyzerPar(request):
    return render(request,'DataAnalyzer/ProtoAnalyzerPar.html')
    pass
def ProtoAnalyzer(request):
    context={}
    global PCAPS, PD
    # PCAPS = rdpcap('ProjectMain/Pcaps/ftp3.pcap')
    if PCAPS == None:
        context = dict()
        context['error'] = '请先上传要分析的数据包...'
        return render(request, "DataAnalyzer/ProtoAnalyzer.html", context)
    else:
        data_dict = common_proto_statistic(PCAPS)       # 常见协议统计IP,IPv6,TCP,UDP,ARP,ICMP,DNS,HTTP,HTTPS,Other
        pcap_len_dict = pcap_len_statistic(PCAPS)       # 数据包大小统计
        pcap_count_dict = most_proto_statistic(PCAPS, PD)  # 最多协议数量统计
        http_dict = http_statistic(PCAPS)                   # #http/https协议统计
        http_dict = sorted(http_dict.items(),
                           key=lambda d: d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)
        dns_dict = dns_statistic(PCAPS)                     # DNS协议统计
        dns_dict = sorted(dns_dict.items(), key=lambda d: d[1], reverse=False)
        dns_key_list = list()
        dns_value_list = list()
        for key, value in dns_dict:
            dns_key_list.append(key.decode('utf-8'))
            dns_value_list.append(value)
        context['data'] = list(data_dict.values())
        context['pcap_len'] = pcap_len_dict
        context['pcap_keys'] = list(pcap_count_dict.keys())
        context['pcap_count'] = pcap_count_dict
        context['http_key'] = http_key_list
        context['http_value'] = http_value_list
        context['dns_key'] = dns_key_list
        context['dns_value'] = dns_value_list
        context['dns_key'] = dns_key_list
    return render(request, 'DataAnalyzer/ProtoAnalyzer.html',context)
# IpMap
def IpMapPar(request):
    return render(request, "DataAnalyzer/IpMapPar.html")
def IpMap(request):
    context = dict()
    global PCAPS, PD
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包..."
        return render(request, "DataAnalyzer/IpMap.html", context)
    else:
        myip = getmyip()                        # 获取本机外网IP
        if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)
            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            myip_geo = get_geo(myip)            #  获取经纬度
            ip_value_list = [(list(d.keys())[0], list(d.values())[0].split(':')[0],list(d.values())[0].split(':')[1],geo_dict.get(list(d.keys())[0]))
                             for d in ip_value_list]
            context['geo_data'] = geo_dict
            context['ip_value'] = ip_value_list
            context['mygeo'] = myip_geo
            return render(request, "DataAnalyzer/IpMap.html", context)
        else:
            context['error'] = '请检查连接网络情况...'
            return render(request, "DataAnalyzer/IpMap.html", context)

'''
异常警告
'''
@require_http_methods(['GET'])
def ExceptWaringPar(request):
    return  render(request,'DataAnalyzer/ExceptWaringPar.html')
@require_http_methods(['GET'])
def ExceptWaring(request):
    context={}
    if PCAPS == None:
        context['error']="请先上传要分析的数据包!"
        return render(request, 'DataAnalyzer/ExceptWaring.html',context)
    else:
        Params = request.GET
        dataid = None
        if('id' in Params):
            dataid=int(Params['id'])
        host_ip = get_host_ip(PCAPS)
        warning_list = exception_warning(PCAPS, host_ip)
        warning_dict = dict()
        for index,war in enumerate(warning_list,1):
            warning_dict[""+str(index)+""] = war
        if len(warning_dict) == 0:
            context['error'] = "数据包中无异常警告！"
            return render(request, 'DataAnalyzer/ExceptWaring.html', context)
        context['waring']=warning_dict
        if dataid:
            if warning_list[int(dataid) - 1]['data']:
                return warning_list[int(dataid) - 1]['data'].replace('\r\n', '<br>')
            else:
                return '<center><h3>无相关数据包详情</h3></center>'
        else:
            return render(request,'DataAnalyzer/ExceptWaring.html', context)

'''

*****************************数据提取********************************

'''
# Web数据
def WebDataPar(request):
    return render(request, 'DataExtract/WebDataPar.html')
def WebData(request):
    context = {}
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataExtract/WebData.html', context)
    else:
        params=request.GET
        host_ip = get_host_ip(PCAPS)
        webdata_list = web_data(PCAPS, host_ip)
        context['webdata']=webdata_list
        if 'id' in params:
            dataid=params['id']
            context['webdata']=webdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
            return JsonResponse(context)
        else:
            return render(request,'DataExtract/WebData.html', context)

# Mail数据
def MailData(request):
    context = {}
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataExtract/maildata.html', context)
    else:
        params= request.GET

        if 'filename' in params :
            filename=params['filename']
        host_ip = get_host_ip(PCAPS)
        mailata_list = mail_data(PCAPS, host_ip)
        context['maildata'] = mailata_list
        if 'id' in params :
            dataid = params['id']
            # return mailata_list[int(dataid)-1]['data'].replace('\r\n',
            # '<br>')
            context['dataid']=dataid
            context['maildata'] = mailata_list[int(dataid)-1]['parse_data']
            return render(request,'DataExtract/mailparsedata.html',context)
        else:
            return render(request,'DataExtract/maildata.html', context)

# FTP数据
def FtpDataPar(request):
    return render(request,'DataExtract/FtpDataPar.html')
def FtpData(request):
    context = {}
    dataid=0
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataExtract/FtpData.html', context)
    else:
        host_ip = get_host_ip(PCAPS)
        ftpdata_list = telnet_ftp_data(PCAPS, host_ip, 21)
        context['ftpdata']=ftpdata_list
        if 'id' in request.GET:
            dataid = request.GET['id']
            return JsonResponse({'data': ftpdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')})
        else:
            return render(request,'DataExtract/FtpData.html',context)

# Telnet数据
def TelnetDataPar(request):
    return render(request,'DataExtract/TelnetDataPar.html')

def TelnetData(request):
    context = {}
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataExtract/TelnetData.html', context)
    else:
        host_ip = get_host_ip(PCAPS)
        telnetdata_list = telnet_ftp_data(PCAPS, host_ip, 23)
        context['telnetdata']=telnetdata_list
        if 'id' in request.GET:
            dataid = request.GET['id']
            return JsonResponse({"data":telnetdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')})
        else:
            return render(request,'DataExtract/TelnetData.html', context)

# 客户端信息
def ClientInfo(request):
    context = {}
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataAnalyzer/ExceptWaring.html', context)
    else:
        clientinfo_list = client_info(PCAPS)
        context['clientinfos']=clientinfo_list
        return render(request,'DataExtract/ClientInfo.html', context)

# 敏感数据
def SenDataPar(request):
    return render(request,'DataExtract/SenDataPar.html')
def SenData(request):
    context = {}
    if PCAPS == None:
        context['error'] = "请先上传要分析的数据包!"
        return render(request, 'DataExtract/SenData.html', context)
    else:
        host_ip = get_host_ip(PCAPS)
        sendata_list = sen_data(PCAPS, host_ip)
        context['sendata']=sendata_list
        if 'id' in request.GET:
            dataid = request.GET['id']
            return JsonResponse({"data":sendata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')})
        else:
            return render(request,'DataExtract/SenData.html', context)

