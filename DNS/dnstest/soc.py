import sys
import socket
import struct
import os
import random

domain = "www.baidu.com"
print(type(domain))
b4 = bytes('www.baidu.com', encoding='UTF-8')
print("b4: ", b4)
request_id = 65535
#2个Byte 长度无符号数
tp=int(129)
header = struct.pack('!HBBHHHH', request_id, tp, 128, 1, 0, 0, 0)
print(header)
headerint = random.randint(0,65535)
print(type(headerint),headerint)
header_ip=struct.pack('!H',headerint)
#print('heip:',header_ip)
hoststr = ''.join(chr(len(x))+x for x in domain.split('.'))
hostbin=hoststr.encode()+b'\x00'
print(hostbin)
data = header_ip+b'\x81\x00\x00\x01\x00\x00\x00\x00\x00\x00'+ hostbin+b'\x00\x00\x01\x00\x01'
tada = data
print(type(tada),'tada:',tada)
#header_flag=\x01\x00 header_qdcount=\x00\x01 ancount=\x00\x01 nscount=\x00\x01 arcount=\x00\x01
#QTYPE=\x00\x01 1 是 A记录
#QCLASS=\x00\x01 默认都是1 
#print(data.encode())
#data = struct.pack('!H', len(data)) + data
#print(struct.pack('!H', len(data)))
#print(data)
#d=struct.pack('!H',129)
#print('d:',d)
#data[2]=data[2] & 129
d=data[2]&(1<<7)
print(type(d),d)
print('data-len:',len(data),type(data))
if data[2] == b'\x01':
    tp=1
    print('递归')
else :
    tp=0
    print('迭代')
da = data.split(b'\x00\x00\x01\x00\x00\x00\x00\x00\x00')
qd=da[0]
print(type(qd),da)
name = ''
i = 0
for x in da[1]:
    n = int(x)
    if n == 0:
        break
    i = i + 1
    if n < 32:
        if len(name):
            name =name + '.'
        name = name + (da[1][i:i + n]).decode() 
print(len(name),type(name),name)
print(data)
(id, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
print(type(id),id, type(flags),flags, type(quests),quests, type(answers),answers,type(author),author, type(addition), addition)
qr = 1 if (flags & (1<<15)) else 0
print('qr:',qr)
x=data[12]  #int 型
print(type(x),x)
i=13
name = ''
while True:
    d = data[i]
    if d == 0:
        break
    if d < 32:
        name = name + '.'
    else:
        name = name + chr(d) 
    i = i + 1
querybytes = data[12:i + 1]
(qtype, classify) = struct.unpack('>HH', data[i + 1:i + 5])
print(type(name),name)
print(type(qtype),qtype,type(classify),classify)
leg=len(data)
print(type(leg),leg)
data=data+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x9c\x00\x07s\xee\xbe\xf0\x02'
print(data)
pand = (data[leg+3] & 255)
if  pand > 0 :     #判断type类型
    print(pand)
(offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[leg:leg+16])
print ("{0}.{1}.{2}.{3}".format(ip1,ip2,ip3,ip4))
rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
print(type(rdip),rdip)
hostip=[]
hostip.append('1452')
hostip.append('1422')
for x in hostip:
    print(x)
doma = 'www..com'
indoma = 'dns1.com'
domains = doma.split('.')
print(domains)
dolen = len(domains)
print('dolen:',dolen)
topdomain = domains[dolen-1] 
print(type(topdomain),topdomain)
if topdomain in indoma :
    print('zaide')
addr=('12556',255)
print(int(addr[1]))
def ggg(n= 5,m =5):
    age(n,m)
def age( n = 1,m = 0):
    print('n:',n,'m:',m)
ggg(8,9)