from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
import json
import threading
from ProjectMain.RealTimeMonitoring.utils import Util
from django.core.paginator import Paginator

'''
1.整个数据表
     paginator.count   数据总数
     paginator.num_pages   总页数
     paginator.page_range   页码的列表
2.当前页
     curuent_page.has_next()   是否有下一页
     curuent_page.next_page_number()   下一页的页码
     curuent_page.has_previous()   是否有上一页
     curuent_page.previous_page_number()   上一页的页码
'''
U = Util.Util()
''' DGA请求'''
# 分页参数
DGA_curuent_page,DGA_pag_range,DGA_curuent_page_num=None,None,None
URL_curuent_page,URL_pag_range,URL_curuent_page_num=None,None,None
def DGArequest(request):
    context={}
    if(DGA_curuent_page):
        context['curuent_Page'] = DGA_curuent_page
        context['curuent_Page_num'] = DGA_curuent_page_num
        context['pag_range'] = DGA_pag_range
        context['maxLen']=len(DGA_pag_range)
        context['end'] = DGA_curuent_page.has_next()
    return render(request, 'DGA/DGArequest.html', context)
# DGA数据查
''' DGA响应'''
def DGAresponse(request):
    context = {}
    return render(request, 'DGA/DGAresponse.html', context)
def DGAquery(request):
    params = request.GET
    sort_type = 'asc'
    if ('dga_type' in params):
        dga_type = params['dga_type']
    if ('sort' in params):
        sort = params['sort']
        if (sort == '-id'):
            sort_type = 'desc'
    sql = "select id,DATE_FORMAT(timestamp,'%Y-%m-%d %H:%i:%S'),src,dst,domain,type,prediction from dga_flow order by id desc"
    result = U.mysqlPool.execute(sql)
    dga_value = list()
    for i, res in enumerate(result):
        dga_value.append(
            {'index': i + 1, 'time': res[1], 'srt': res[2], 'dst': res[3], 'domain': res[4], 'type': res[5],
             'pre': res[6]})
    paginator = Paginator(dga_value, 15)
    pag_num = paginator.num_pages
    global DGA_curuent_page, DGA_pag_range, DGA_curuent_page_num
    DGA_curuent_page_num = 1
    if ('page' in params and params['page'] != ''):
        DGA_curuent_page_num = int(params['page'])
    DGA_curuent_page = paginator.page(DGA_curuent_page_num)
    if pag_num < 11:  # 判断当前页是否小于11个
        DGA_pag_range = paginator.page_range
    elif pag_num > 11:
        if DGA_curuent_page_num < 6:
            DGA_pag_range = range(1, 11)
        elif DGA_curuent_page_num > pag_num - 5:
            DGA_pag_range = range(pag_num - 9, pag_num + 1)
        else:
            DGA_pag_range = range(DGA_curuent_page_num - 5, DGA_curuent_page_num + 5)  # 当前页+5等于最大页时
    context = {}
    context['curuent_Page'] = DGA_curuent_page
    context['curuent_Page_num'] = DGA_curuent_page_num
    context['pag_range'] = DGA_pag_range
    return render(request, 'DGA/DGArequestAuto.html', context)


# dga开始监测
def DGAstart(request):
    # U.Sniff_DGA()
    thread_DGA = threading.Thread(target=U.Sniff_DGA)
    thread_DGA.start()
    returnJson = json.dumps({'result': '200'})
    return HttpResponse(returnJson, content_type="application/json")
# dga监测停止
def DGAstop(request):
    U.DGA_Flag = 0
    return JsonResponse({'result': '200'})
def DGAdel(request):
    try:
        sql = "delete from dga_flow"
        U.mysqlPool.execute(sql,commit=True)
    except Exception:
        return JsonResponse({'result': '300'})
    return JsonResponse({'result': '200'})

''' 
URL流量监测
'''
def URLrequest(request):
    context = {}
    if (URL_curuent_page):
        context['curuent_Page'] = URL_curuent_page
        context['curuent_Page_num'] = URL_curuent_page_num
        context['pag_range'] = URL_pag_range
        context['maxLen'] = len(URL_pag_range)
        context['end'] = URL_curuent_page.has_next()
    # context['request']=result
    return render(request, 'URL/URLrequest.html', context)
    pass


def URLquery(request):
    params=request.GET
    sql = "select id,DATE_FORMAT(timestamp,'%Y-%m-%d %H:%i:%S'),src,dst,url,status,pre from url_flow order by id desc"
    result = U.mysqlPool.execute(sql)
    url_list = list()
    for i, res in enumerate(result):
        url_list.append(
            {'index': i+1, 'time': res[1], 'srt': res[2], 'dst': res[3], 'url': res[4], 'status': res[5],
             'pre': res[6]})
    context = {}
    paginator = Paginator(url_list, 15)
    pag_num = paginator.num_pages
    global URL_curuent_page, URL_pag_range, URL_curuent_page_num
    URL_curuent_page_num = 1
    if ('page' in params and params['page'] != ''):
        URL_curuent_page_num = int(params['page'])
    URL_curuent_page = paginator.page(URL_curuent_page_num)
    if pag_num < 11:  # 判断当前页是否小于11个
        URL_pag_range = paginator.page_range
    elif pag_num > 11:
        if URL_curuent_page_num < 6:
            URL_pag_range = range(1, 11)
        elif URL_curuent_page_num > pag_num - 5:
            URL_pag_range = range(pag_num - 9, pag_num + 1)
        else:
            URL_pag_range = range(URL_curuent_page_num - 5, URL_curuent_page_num + 5)  # 当前页+5等于最大页时
    context = {}
    context['curuent_Page'] = URL_curuent_page
    context['curuent_Page_num'] = URL_curuent_page_num
    context['pag_range'] = URL_pag_range
    return render(request, 'URL/URLrequestAuto.html', context)
    pass


def URLstart(request):
    thread_URL = threading.Thread(target=U.Sniff_URL)
    thread_URL.start()
    returnJson = json.dumps({'result': '200'})
    return HttpResponse(returnJson, content_type="application/json")


def URLstop(request):
    U.URL_Flag = 0
    return JsonResponse({'result': '200'})


def URLdel(request):
    try:
        sql = "delete from url_flow"
        U.mysqlPool.execute(sql,commit=True)
    except Exception:
        return JsonResponse({'result': '300'})
    return JsonResponse({'result': '200'})
