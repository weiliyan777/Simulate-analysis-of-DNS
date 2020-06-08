#!/usr/bin/python

#import configparser
import socket
import time   
import os
import re
import struct
 
def dns_codec(hostname):
    '''
    Function:请求消息编码
    Input：hostname：主机名，如www.baidu.com
    Output: 编码后的字节流
    author: socrates
    date:2012-12-14
    '''
    index = os.urandom(2)
    hoststr = ''.join(chr(len(x))+x for x in hostname.split('.'))
    data = '%s\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00%s\x00\x00\x01\x00\x01' % (index, hoststr)
    data = struct.pack('!H', len(data)) + data
    return data
 
def dns_decode(in_sock):
    '''
    Function:响应消息解码
    Input：in_sock：接收消息的socket
    Output:解码后的内容
    author: socrates
    date:2012-12-14
    '''
    rfile = in_sock.makefile('rb')
    size = struct.unpack('!H', rfile.read(2))[0]
    data = rfile.read(size)
    iplist = re.findall('\xC0.\x00\x01\x00\x01.{6}(.{4})', data)
    return ['.'.join(str(ord(x)) for x in s) for s in iplist]  
    
def dns_sendmsg():
    '''
    Function:通过socket发送DNS查询消息
    Input：None
    Output:None
    author: socrates
    date:2012-12-14
    '''
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  
    except socket.error as e:
        print ('create socket return error. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))
    
    #连接服务器并发送消息        
    try:
        #连接服务端
        sock.connect(('127.0.0.1', 53))  
        
        while(True):
            
            #发送频率
            time.sleep(2) 
            
            #发送消息 
            msg_1 = input('please input work: ')
            sock.sendall(dns_codec(msg_1))  
            
            #接收并打印消息
            print (dns_decode(sock))  
            
    except socket.error as e:  
        print ('connect server failed. errno = %d, errmsg = %s' % (e.args[0], e.args[1]))
             
    sock.close()     
    
    
if __name__ == '__main__': 
     dns_sendmsg()
