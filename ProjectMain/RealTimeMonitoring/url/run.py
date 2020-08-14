# -*- coding: utf-8 -*-
import warnings
warnings.filterwarnings("ignore")
from scapy.all import *
import scapy_http.http
import os
import keras
import numpy as np
import string
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from requests import *
import inspect
import threading
import ctypes
from mysql.connector import connect
conf.iface='Intel(R) Dual Band Wireless-AC 3165'
# 实际当中，捆绑方法。实名制条件下，找到宿主
# 找到宿主，切断源头。
# 宿源最终。终端设备。
# 不同方式检测，
# 规避不同包
# 用户网域端，用户隐私，可以公开分析的格式。
#conf.iface='Realtek PCIe GBE Family Controller'

# 数据库连接
mydb=connect(
    host='localhost',
    user='root',
    passwd='123456',
    database='dgamonitoring'
)

print('**** Connect mysql ****')
mycursor = mydb.cursor()
print('**** Connect success ****')
sql='delete from url_response'
sql1='delete from url_request'
mycursor.execute(sql)
mycursor.execute(sql1)
mydb.commit()
print('**** Load model ****')
model=keras.models.load_model("./model/URL_LSTM.h5")
f=open('./model/url_char_dict.txt',encoding='utf8')
char=f.read()
char_dict=eval(char)
f.close()
#Capture and Filter DGA
def URL_callBack(packet):
    if packet:
        i =0
        try:
            p=packet["HTTP"]
            try:
                a = p["HTTPRequest"]
                if(a.Host!=None):
                    Url=bytes.decode(a.Host)+bytes.decode(a.Path)
                    url=[[char_dict[x] for x in Url]]
                    url=keras.preprocessing.sequence.pad_sequences(url,maxlen=char_dict['maxlen'])
                    pre=np.max(model.predict(url))
                    print("Request url is :",Url,"pre :",pre)
                    sql = "insert into url_request(url,pre) values(%s,%s)"
                    val = (Url, float(pre))
                    mycursor.execute(sql,val)
                    mydb.commit()
            except IndexError:
                pass
            try:
                a = p["HTTPResponse"]
                print('响应Url:', a.Location)
            except IndexError:
                pass
            try:
                a = p["Raw"]
                try:
                    b = p["HTTPRequest"]
                    print("请求数据:", a.load)
                except IndexError:
                    pass
                try:
                    b = p["HTTPResponse"]
                    print('响应数据', a.load)
                except IndexError:
                    pass
                '''
                对数据解析
                也可将数据包保存下来
                '''
            except IndexError:
                pass
        except IndexError:
            pass
def _async_raise(tid, exctype):
  """raises the exception, performs cleanup if needed"""
  tid = ctypes.c_long(tid)
  if not inspect.isclass(exctype):
    exctype = type(exctype)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
    # """if it returns a number greater than one, you're in trouble,
    # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")
def stop_thread(thread):
  _async_raise(thread.ident, SystemExit)
flag=1
def hello():
    print("hello")
    while flag:
        sniff(prn=URL_callBack, filter='tcp port 80',count=2)

if __name__ == "__main__":
    print('**** Start Monitoring traffic ****')
    sniff(prn=URL_callBack, filter='tcp port 80')
    #终止
    time.sleep(50)
    flag=0
    print("stoped")
#   if __name__ == '__main__':
#
#
#
#     t=threading.Thread(target=sniff(prn=URL_callBack,filter='tcp port 80'))
#     # dkpt=sniff(prn=URL_callBack,filter='tcp port 80')
#     t.start()
#     print("线程开始")
#     stop_thread(t)
#     print("线程停止")

