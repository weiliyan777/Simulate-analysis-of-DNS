import socket
import threading
import time
import sys
import json
import random
import struct

def find_in_file(domain,data,rd):
    ##打开缓存文件查找
    flag = 0
    jsons = []
    fopen = open("D:\VS code\.vscode\DNS\soc_com.txt",'r')
    for line in fopen:
        if line != '\n':
            jsObj = json.loads(line)
            if jsObj['name'] == domain :
                jsons.append(jsObj)
                flag=1
    fopen.close()
    ipnum = len(jsons)
    ###先生成header和question部分
    respdata = dnsrespose_no(data,rd,ipnum,0,0)
    if ipnum > 0 :
        i=0
        while ipnum :
            ###循环补上answers部分
            respdata = dnsrespose_ans(respdata,jsons[i])
            i = i + 1
            ipnum = ipnum -1
    return respdata,flag

def dnsrespose_no(data,rd,answer = 0,author = 0,addition = 0):
    #根据查询类型分类 将报文改为响应报文，并设置本服务器可支持递归查询
    if rd :
        flag1=129
        temp = data.split(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        header_id = temp[0]
    else:
        flag1=128
        temp = data.split(b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        header_id = temp[0]
    flag2 = 128
    #设置返回count的值
    qdcount = 1
    ancount = answer
    nscount = author
    arcount = addition
    header_flag=struct.pack('!BBHHHH', flag1, flag2, qdcount, ancount, nscount, arcount)
    reqdata=header_id+header_flag+temp[1]
    return reqdata

def dnsrespose_addi(reqdata,nsdomain,name_offset):
    count_addi = len(nsdomain)
    i=0
    while count_addi:
        addiname = 192*256+name_offset[i]  #192*256 = \xc0\x00 
        additype = int(nsdomain[i]['type'])
        addiclass = int(nsdomain[i]['rrclass'])
        addittl = int(nsdomain[i]['ttl'])
        addirdlength = int(nsdomain[i]['rdlength'])
        addirdata = nsdomain[i]['rdata']
        addipartdata = struct.pack('!HHHLH', addiname, additype, addiclass, addittl, addirdlength)
        ###将ip转换为字节
        s = addirdata.split('.')
        hostip =  struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
        ##合并当前所有字节
        reqdata = reqdata + addipartdata + hostip
        #下一次循环
        i=i+1
        count_addi=count_addi-1
    return reqdata

def dnsrespose_auth(data,nsdomain,rd):
    #根据查询类型分类 将报文改为响应报文，并设置本服务器可支持递归查询
    if rd :
        flag1=129
        temp = data.split(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        header_id = temp[0]
    else:
        flag1=128
        temp = data.split(b'\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        header_id = temp[0]
    flag2 = 128
    #设置返回count的值
    qdcount = 1
    ancount = 0
    nscount = len(nsdomain)
    arcount = len(nsdomain)
    header_flag=struct.pack('!BBHHHH', flag1, flag2, qdcount, ancount, nscount, arcount)
    reqdata=header_id+header_flag+temp[1]      #修改部分位 ， 未加Authoritative和Additional
    #获取Authoritative部分字段数据并打包成字节
    count_auth = len(nsdomain)
    i=0
    name_offset=[]  ##用来记录名称偏移量
    while count_auth:
        authname = 49164
        authtype = 2
        authclass = 1
        authttl = int(nsdomain[i]['ttl'])
        authrdlength = int(nsdomain[i]['rdlength'])
        authrdata = nsdomain[i]['name']
        authpartdata = struct.pack('!HHHLH', authname, authtype, authclass, authttl, authrdlength)
        #将顶级域名从字符串转换为字节
        hoststr = ''.join(chr(len(x))+x for x in authrdata.split('.'))
        hostbin=hoststr.encode()+b'\x00'
        #记录名称偏移量
        name_offset.append(len(reqdata+authpartdata))
        ##合并当前所有字节
        reqdata = reqdata + authpartdata + hostbin
        #下一次循环
        i=i+1
        count_auth=count_auth-1
    #返回请求数据（已包含header、question、authentic）
    return reqdata,name_offset


###生成answer段内容的响应报文
def dnsrespose_ans(respdata,jsont):
    #获取answer部分字段数据并打包成字节
    ansname = 49164
    anstype = int(jsont['type'])
    ansclass = int(jsont['rrclass'])
    ansttl = int(jsont['ttl'])
    ansrdlength = int(jsont['rdlength'])
    ansrdata = jsont['rdata']
    anspartdata = struct.pack('!HHHLH', ansname, anstype, ansclass, ansttl, ansrdlength)
    ###将ip转换为字节
    s = ansrdata.split('.')
    hostip =  struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
    #合并所有字节并返回
    respdata = respdata + anspartdata + hostip
    print(respdata)
    return respdata
     

def Analysis_req(data):
    rd = data[2] & 1
    data = data.split(b'\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    name = ''
    i = 0
    for x in data[1]:
        n = int(x)
        if n == 0:
            break
        i = i + 1
        if n < 32:
            if len(name):
                name =name + '.'
            name = name + (data[1][i:i + n]).decode() 
    return name,rd

def socket_service():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        loc_addr='127.0.0.3'
        port=6688
        s.bind((loc_addr, port))
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print('here is dns.com-servise and waiting msg...')
 
    while 1:
        data, addr = s.recvfrom(1024)   #data为dns请求报文
        print('已收到',addr,'的请求数据......')
        #gtch=input()
        time.sleep(1)
        hostname,rd=Analysis_req(data)     #hostname为请求域名 rd为递归与否
        flag=0
        respdata,flag = find_in_file(hostname,data,rd)
        if flag :
            s.sendto(respdata,addr)
            print("在文件中找到，并已经成功发回")
        else:        #####缓存表中没有找到
            #res='该服务器本地缓存无此记录'
            domains = hostname.split('.')
            dolen = len(domains)
            if dolen < 2 : 
                respdata = dnsrespose_no(data,rd)
                s.sendto(respdata,addr)
                print('已对servise',addr,'发送响应报文')
            else:
                topdomain = domains[dolen-2] +'.'+ domains[dolen-1]
                nsdomain=[]
                ##从文件中取出匹配顶级域名的信息
                fopen = open("D:\VS code\.vscode\DNS\soc_com_ns.txt")
                for line in fopen:
                    if line != '\n':
                        jsObj = json.loads(line)
                        if  topdomain in jsObj['name']:
                            nsdomain.append(jsObj)
                fopen.close()
                len_nsdomain = len(nsdomain)
                if  len_nsdomain > 0 :
                    reqdata,name_offset = dnsrespose_auth(data,nsdomain,rd)
                    reqdata = dnsrespose_addi(reqdata,nsdomain,name_offset)
                    s.sendto(reqdata,addr)
                    print('已对servise',addr,'发送响应报文')
                else :  ##NS域也找不到
                    respdata = dnsrespose_no(data,rd)
                    s.sendto(respdata,addr)
                    print('已对servise',addr,'发送响应报文')

        print('here is dns.com-servise and waiting msg...')
    s.close()

if __name__ == '__main__':
    socket_service()