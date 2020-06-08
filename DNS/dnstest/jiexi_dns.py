# coding:utf-8
import socket
import os
import re

def reply_to_iplist(data):
    print(data)
    assert isinstance(data, basestring)
    iplist = ['.'.join(str(ord(x)) for x in s) for s in re.findall('\xc0.\x00\x01\x00\x01.{6}(.{4})', data) if all(ord(x) <= 255 for x in s)]
    return iplist

def domain_to_ip(dnsserver,domain):
    dnsserver = dnsserver
    seqid = os.urandom(2)
    host = ''.join(chr(len(x))+x for x in domain.split('.'))
    data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (seqid, host)
    sock = socket.socket(socket.AF_INET,type=socket.SOCK_DGRAM)
    sock.settimeout(None)
    print(1553)
    sock.sendto(data.encode('utf-8'), (dnsserver, 53))
    print(127773)
    datd = sock.recv(1024)
    print(123)
    return reply_to_iplist(datd.decode())

dnsServer = "127.0.0.1"
sina = domain_to_ip(dnsServer,"sina.com")
google = domain_to_ip(dnsServer,"google.com")
youbube = domain_to_ip(dnsServer,"youtube.com")
print("sina:",sina)
print("google:",google)
print("youbube:",youbube)