#coding:utf-8
import warnings
warnings.filterwarnings("ignore")
import time
import tensorflow as tf
import pickle
import numpy as np
from scapy.all import *
import os
import string
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from requests import *
from mysql.connector import connect

conf.iface='Intel(R) Dual Band Wireless-AC 3165'
# 实际当中，捆绑方法。实名制条件下，找到宿主
# 找到宿主，切断源头。
# 宿源最终。终端设备。
# 不同方式检测，
# 规避不同包
# 用户网域端，用户隐私，可以公开分析的格式。
#conf.iface='Realtek PCIe GBE Family Controller'
mydb=connect(
    host='localhost',
    user='root',
    passwd='123456',
    database='dgamonitoring'
)

print('**** Connect mysql ****')
mycursor = mydb.cursor()
print('**** Connect success ****')
sql='delete from dga_response'
sql1='delete from dga_request'
mycursor.execute(sql)
mycursor.execute(sql1)
mydb.commit()
print('**** Load model ****')
model=tf.keras.models.load_model("./model/DGA.h5")
f=open('./model/DGA_char_dict.txt')
char=f.read()
char_dict=eval(char)
f.close()


#Capture and Filter DGA
def capture(packet):

    if packet:
        #print("抓包：",packet)
        i =0
        for p in packet:
            # 有的没有IP 只有IPV9
            # print(p[IP].src)
            # 查询/响应标志，0为查询，1为响应
            qr = str(p[i][DNS].qr)
            # 表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure）
            rcode = str(p[i][DNS].rcode)
            if '0' in qr:
                qr = 'Query'
                # 域名
                qname = p[i][DNS].qd.qname
                if type(qname) == bytes:
                    qname = (qname.decode('utf-8'))[:-1]
                domainArray=qname.split('.')[:-1]
                domain=[[char_dict[x] for x in y]  for y in domainArray if len(y) >1]
                domain = tf.keras.preprocessing.sequence.pad_sequences(domain, maxlen=char_dict['maxlen'])
                pre=np.max(model.predict(domain))
                sql = "insert into dga_request(domain,pre) values(%s,%s)"
                val = (qname,float(pre))
                mycursor.execute(sql, val)
                mydb.commit()
                print("Found DGA Request:-->",qname,"--- Pre :",pre)
            if '1' in qr:
                #
                if '0' in rcode:
                    for j in range(10):
                        try:
                            rrname = p[j][DNS].an[j].rrname
                            rdata = p[j][DNS].an[j].rdata
                            if type(rrname) == bytes:
                                rrname = (rrname.decode('utf-8'))[:-1]
                            if type(rdata) == bytes:
                                rdata = (rdata.decode('utf-8'))[:-1]
                                # print("数据"+rdata)
                            domainArray = rrname.split('.')[:-1]
                            domain = [[char_dict[x] for x in y] for y in domainArray if len(y) >1]
                            domain = tf.keras.preprocessing.sequence.pad_sequences(domain, maxlen=char_dict['maxlen'])
                            pre = np.max(model.predict(domain))
                            sql = "insert into dga_response(domain,pre) values(%s,%s)"
                            val = (rrname, float(pre))
                            mycursor.execute(sql, val)
                            mydb.commit()
                            print("Found DGA Response-->",rrname,"---Pre :" ,pre)
                        except Exception as e:
                            pass

            i = i + 1

if __name__ == '__main__':
    print('**** Start Monitoring traffic ****')
    sniff(prn=capture,filter='udp port 53')
    # sniff(prn=capture,iface='Realtek PCIe GBE Family Controller',filter='udp port 53',count=20)
    while True:
        time.sleep(86400)
