#coding:utf-8
import warnings
warnings.filterwarnings("ignore")
import ProjectMain.RealTimeMonitoring.utils.config as config
import os
os.environ['CUDA_VISIBLE_DEVICES']='-1'
import tensorflow as tf
import keras
import numpy as np
# 要想监测Http请求必须要引入这个包
from scapy.all import *
import scapy_http

import os
import requests
import re
import urllib.request
import urllib.parse
import urllib.error
import json
from bs4 import BeautifulSoup
from aip import AipNlp
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
from mysql.connector import pooling,connect
from aip import AipImageCensor
APP_ID = '17305394'
API_KEY = 'PMK6rSfE6jZvk3yQgl0o1MRx'
SECRET_KEY = 'o46XymQZll0C9BAOl1BHBE83v20ntI8r'
class Util:
    class MysqlPool(object):
        """
        Mysql连接池
        """
        def __init__(self,host="127.0.0.1", port="3306", user="root",
                 password="123456", database="dgamonitoring", pool_name="mypool",
                 pool_size=10):
            res = {}
            self._host = host
            self._port = port
            self._user = user
            self._password = password
            self._database = database
            res["host"] = self._host
            res["port"] = self._port
            res["user"] = self._user
            res["password"] = self._password
            res["database"] = self._database
            self.dbconfig = res
            self.pool = self.create_pool(pool_name=pool_name, pool_size=pool_size)

        def create_pool(self, pool_name="mypool", pool_size=10):
            pool = pooling.MySQLConnectionPool(
                pool_name=pool_name,
                pool_size=pool_size,
                pool_reset_session=True,
                **self.dbconfig)
            return pool
        def close(self, conn, cursor):
            cursor.close()
            conn.close()
        def execute(self, sql, args=None, commit=False):
            """
            执行函数
            args支持（1,2,3，）形式
            DQL语句不用设置commit参数
            操作语句需要设置
          """
            # get connection form connection pool instead of create one.
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            if args:
                cursor.execute(sql, args)
            else:
                cursor.execute(sql)
            if commit is True:
                conn.commit()
                self.close(conn, cursor)
                return None
            else:
                res = cursor.fetchall()
                self.close(conn, cursor)
                return res
        def executemany(self, sql, args, commit=False):

            conn = self.pool.get_connection()
            cursor = conn.cursor()
            cursor.executemany(sql, args)
            if commit is True:
                conn.commit()
                self.close(conn, cursor)
                return None
            else:
                res = cursor.fetchall()
                self.close(conn, cursor)
                return res
    def __init__(self):
        # 测试数据
        test_case = [np.zeros(10)]
        print('**** Load dict ****')
        f = open(config._URL['URL_DICT_PATH'], encoding='utf8')
        char = f.read()
        url_dict = eval(char)
        f = open(config._DGA['DGA_DICT_PATH'], encoding='utf8')
        char = f.read()
        dga_dict = eval(char)
        f.close()
        self.DGA_dict=dga_dict
        self.Url_dict=url_dict
        # 文本检测返回值
        self.URL_labels = ['暴恐违禁', '文本色情', '政治敏感', '恶意推广', '低俗辱骂', '低质灌水']
        print('**** Load model ****')
        ''' 创建加载模型的所需变量'''
        self.graph1 = tf.Graph()
        self.sess1 = tf.Session(graph=self.graph1)
        self.graph2 = tf.Graph()
        self.sess2 = tf.Session(graph=self.graph2)
        '''保证模型加载在一个图中，以便再使用模型时不为空'''
        with self.sess1.as_default():
            with self.graph1.as_default():
                self.DGAModel=tf.keras.models.load_model(config._DGA['DGA_MODEL_PATH'])
                # 初始化的时候要进行一次模拟测试，防止layer找不到
                test_case = tf.keras.preprocessing.sequence.pad_sequences(test_case, 
                                                        maxlen=self.DGA_dict['maxlen'], )
                self.DGAModel.predict(test_case, verbose=0)
                print('DGA模型初始化成功')
        keras.backend.clear_session()
        with self.sess2.as_default():
            with self.graph2.as_default():
                self.UrlModel=keras.models.load_model(config._URL['URL_MODEL_PATH'])
                test_case = keras.preprocessing.sequence.pad_sequences(test_case,
                                                                       maxlen=self.Url_dict['maxlen'], )
                self.UrlModel.predict(test_case, verbose=0)
                print('URL模型初始化成功')
        self.iface= config.IFACE
        self.DGA_Flag=1
        self.URL_Flag=1
        self.mydb=connect(
            host='localhost',
            user='root',
            passwd='123456',
            database='dgamonitoring'
        )
        print('**** Connect mysql ****')
        self.Mycursor=self.mydb.cursor()
        self.mysqlPool=self.MysqlPool()
        print('**** Connect success ****')
        self.client = AipImageCensor(APP_ID, API_KEY, SECRET_KEY)
        pass
    def Sniff_DGA(self):
        # 清空数据
        # sql = 'delete from dga_response;'
        # self.Mycursor.execute(sql)
        # self.mydb.commit()
        # self.mysqlPool.execute(sql,commit=True)
        print('**** Start Monitoring traffic ****')
        # 进程循环监测
        self.DGA_Flag=1
        while self.DGA_Flag:
            sniff(prn=self.callback_DGA,iface=self.iface, filter='udp port 53',count=2)
        self.DGA_Flag=1

        # sniff(prn=capture,iface='Realtek PCIe GBE Family Controller',filter='udp port 53',count=20)
    def callback_DGA(self,packet):
        if packet:
            # print("抓包：",packet)
            i = 0
            for p in packet:
                # 有的没有IP 只有IPV9
                # print(p[IP].src)
                # 查询/响应标志，0为查询，1为响应
                qr = str(p[i][DNS].qr)
                src=p[i][IP].src
                dst=p[i][IP].dst
                # 表示返回码，0表示没有差错，3表示名字差错，2表示服务器错误（Server Failure）
                rcode = str(p[i][DNS].rcode)
                if '0' in qr:
                    qr = 'Query'
                    # 域名
                    qname = p[i][DNS].qd.qname
                    if type(qname) == bytes:
                        qname = (qname.decode('utf-8'))[:-1]
                    domainArray = qname.split('.')[:-1]
                    domain = [[self.DGA_dict[x] for x in y] for y in domainArray if len(y) > 1]
                    domain = tf.keras.preprocessing.sequence.pad_sequences(domain, maxlen=self.DGA_dict['maxlen'])
                    with self.sess1.as_default():
                        with self.graph1.as_default():
                            pre = np.max(self.DGAModel.predict(domain))
                    # dga_request=Request(domain=domain,pre=float(pre))
                    # dga_request.save()
                    oldQname=''
                    sql = "insert into dga_flow(src,dst,domain,type,prediction) values(%s,%s,%s,%s,%s)"
                    val = (src,dst,qname,'request', float(pre))
                    self.mysqlPool.execute(sql, val, commit=True)
                    # self.Mycursor.execute(sql, val)
                    # self.mydb.commit()
                    print("Found DGA Request:-->", qname, "--- Pre :", pre)
                if '1' in qr:
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
                                domain = [[self.DGA_dict[x] for x in y] for y in domainArray if len(y) > 1]
                                domain = tf.keras.preprocessing.sequence.pad_sequences(domain,maxlen=self.DGA_dict['maxlen'])
                                with self.sess1.as_default():
                                    with self.graph1.as_default():
                                        pre = np.max(self.DGAModel.predict(domain))
                                oldRname=''
                                sql = "insert into dga_flow(src,dst,domain,type,prediction) values(%s,%s,%s,%s,%s)"
                                val = (src, dst, rrname, 'response', float(pre))
                                self.mysqlPool.execute(sql, val, commit=True)
                                print("Found DGA Response-->", rrname, "---Pre :", pre)
                            except Exception as e:
                                pass
                i = i + 1
    '''  
    监测URL 
    '''
    def Sniff_URL(self):
        # sql = 'delete from URl_response'
        # sql1 = 'delete from URl_request'
        # self.Mycursor.execute(sql)
        # self.Mycursor.execute(sql1)
        # self.mydb.commit()
        print('**** StartMonitoring traffic ****')
        self.URL_Flag = 1
		# 线程开启监测tcp 80端口
        while self.URL_Flag:
            sniff(prn=self.callBack_URL,iface=self.iface, filter='tcp',count=5)
        # sniff(prn=capture,iface='Realtek PCIe GBE Family Controller',filter='udp port 53',count=20)
        self.URL_Flag=1
        print("****** 监测结束 *****")
        pass
    def callBack_URL(self,packet):
        if packet:
            i = 0
            src='0.0.0.0'
            dst='0.0.0.0'
            if(packet.haslayer(IP)):
                src=packet[IP].src
                dst=packet[IP].dst
            try:
                if packet.haslayer('HTTP'):
                    p = packet["HTTP"]
                    try:
                        if p.haslayer('HTTPRequest'):
                            a = p["HTTPRequest"]
                            method=bytes.decode(a.Method)
                            if (a.Host != None):
                                Url = 'http://'+bytes.decode(a.Host) + bytes.decode(a.Path)
                                url = [[self.Url_dict[x] for x in Url]]
                                url = keras.preprocessing.sequence.pad_sequences(url, maxlen=self.Url_dict['maxlen'])
                                with self.sess2.as_default():
                                    with self.graph2.as_default():
                                        pre = np.max(self.UrlModel.predict(url))
                                if (pre>=0.7):
                                    '''当url恶意率超过0.7，进行该网页爬取分析'''
                                    t=threading.Thread(target=self.AnalysisUrl(Url))
                                    t.start()
                                print("Request url is :", Url, "pre :", pre)
                                sql = "insert into url_flow(src,dst,url,pre) values(%s,%s,%s,%s)"
                                val = (src,dst,Url, float(pre))
                                self.mysqlPool.execute(sql, val, commit=True)
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

    def getBaiduTextDivideRes(self, text):
        url = 'https://aip.baidubce.com/rest/2.0/antispam/v2/spam?access_token=24.d6402afd2e5dc564214b9a69a68d48fd.2592000.1571732535.282335-17305394'
        data = urllib.parse.urlencode({'content': text}).encode(encoding='utf8')
        request = urllib.request.Request(url, data=data)
        # 设置请求头
        request.add_header('Content-Type', 'application/x-www-form-urlencoded')
        response = urllib.request.urlopen(request)
        res = response.read()
        j = json.loads(res.decode('utf8'))
        review = j.get('result').get('review')
        reject = j.get('result').get('reject')
        print(review, reject)
        return review, reject

    def AnalysisUrl(self, url):
        req = urllib.request.Request(url)
        try:
            res = urllib.request.urlopen(req, timeout=5)
            result = res.read()
            html = BeautifulSoup(result.decode('utf8'), 'lxml')
            # 正则过滤
            text = html.get_text(strip=True)
            if len(text) > 5000:
                limit = 0
                while 1:
                    # 每次查5000字
                    if len(text[limit:limit + 5000]) == 0:
                        break
                    res = self.client.textCensorUserDefined((text[limit:limit + 5000]))
                    if res['conclusion'] != '合规':
                        result_list = list()
                        try:
                            datas = res['data']
                            for data in datas:
                                if (data['msg'] != '存在百度官方默认违禁词库不合规'):
                                    result_list.append(data['msg'].strip("存在").strip("不合规"))
                        except Exception as e:
                            print(e)
                    limit += 5000
            else:
                res = self.client.textCensorUserDefined((text))
                if res['conclusion'] != '合规':
                    result_list = list()
                    try:
                        datas = res['data']
                        for data in datas:
                            if(data['msg']!='存在百度官方默认违禁词库不合规'):
                                result_list.append(data['msg'].strip("存在").strip("不合规"))
                    except Exception as e:
                        print(e)
            sql = "update url_flow set status=%s where url= %s"
            val = (str(result_list),url)
            self.mysqlPool.execute(sql, val, commit=True)
        except urllib.error.URLError:
            print('网页不可访问')


# 实际当中，捆绑方法。实名制条件下，找到宿主
# 找到宿主，切断源头。
# 宿源最终。终端设备。
# 不同方式检测，
# 规避不同包
# 用户网域端，用户隐私，可以公开分析的格式。
