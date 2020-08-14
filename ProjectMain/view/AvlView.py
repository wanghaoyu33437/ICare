# coding=utf-8
from django.http import HttpResponse,JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import os
import shutil
from ProjectMain.utils.AVLScanner.AVlSCcanner import Scanner
AVLSCANNER_PATH='ProjectMain/AVLFolder/'
AVLResult=None
def AVLSelectFilePar(request):
    return render(request,'AVLSDK/AVLSelectFilePar.html')
def AVLSelectFile(request):
    return render(request,'AVLSDK/AVLSelectFile.html')
@require_http_methods(['POST'])
@csrf_exempt
def AVLScannerFiles(request):
    # 保存再删除
    files=request.FILES.getlist('files')
    data=None
    if len(files) == 0:
        return JsonResponse({'success': False, 'error': '上传数据包格式不正确...'})
    else :
        if not os.path.exists(AVLSCANNER_PATH):
            os.mkdir(AVLSCANNER_PATH)
            if len(files)==1:
                with open(AVLSCANNER_PATH + files[0].name, 'wb') as f:
                    for chunk in files[0].chunks():
                        f.write(chunk)
                data=Scanner(os.path.join(os.getcwd(),AVLSCANNER_PATH + files[0].name))
            else:
                for file in files:
                    with open(AVLSCANNER_PATH + file.name, 'wb') as f:
                        for chunk in file.chunks():
                            f.write(chunk)
                data = Scanner(os.path.join(os.getcwd(), AVLSCANNER_PATH),0)
        shutil.rmtree(AVLSCANNER_PATH)
    global AVLResult
    AVLResult=data
    return JsonResponse({'success':True,"data":data})
def ShowAVLResult(request):
    context={}
    context['AVLs']=AVLResult
    return render(request,'AVLSDK/ShowAVLResult.html',context)