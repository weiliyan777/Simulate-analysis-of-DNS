
import socket
import sys
import random
import struct
 
def outbasicdata(ip,flags,quests,answers,author,addition):
    print('Transaction ID: ',hex(ip))
    print('Flags: ',hex(flags),' Standard query')
    qr = 1 if (flags & (1<<15)) else 0
    opcode =(flags & (15<<11))>>11
    stropcode = ''
    i=0
    for i in range (4-len(str(opcode))) :
        stropcode = stropcode + '0'
    stropcode = stropcode + str(opcode)
    tc = (flags & (1<<9))>>9
    rd = (flags & (1<<8))>>8
    Z = (flags & (1<<6))>>6
    nona = (flags & (1<<4))>>4
    print('  ',qr,'... .... .... = Response: Message is a query',sep="")
    print('  .',stropcode,'... .... .... = Opcode: Standard query (',opcode,')',sep="")
    print('  .... ..',tc,'. .... .... = Truncated: Message is not truncated',sep="")
    print('  .... ...',rd,' .... .... = Recursion desired: Dont do query recursively',sep="")
    print('  .... .... .',Z,'.. .... = Z: reserved (',Z,')',sep="")
    print('  .... .... ...',nona,' .... = Non-authenticated data: Unacceptable',sep="")
    print('Questions:',quests)
    print('Answer RRs:',answers)
    print('Authority RRs:',author)
    print('Additional RRs:',addition)

def get_ser_name(ip):
    ser_name = ''
    fopen=open("D:\VS code\.vscode\DNS\soc_NandIP.txt",'r')
    for line in fopen:
        if line != '\n':
            if ip in line :
                data = line.split(',')
                ser_name = str(data[0])
                break
    fopen.close()
    NandIP = (ser_name,ip)
    return NandIP

def get_port(ip):
    port=int(0)
    fopen=open("D:\VS code\.vscode\DNS\soc_serv_port.txt",'r')
    for line in fopen:
        if line != '\n':
            #print (line)
            #print(type(line))
            if ip in line :
                data = line.split(',')
                port = int(data[1])
                break
            #print(data)
    fopen.close()
    return port

def anal_resp_addi(domain,data,n):
    (offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[n:n+16])
    rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
    Type = 'A'
    if rdtype == 1 :
        Type = 'A'
    Cla = 'IN'
    if rdclass == 1 :
        Cla = 'IN'
    print('\nAddition:')
    output = 'Name:'+domain+'\nType:'+Type+'\nClass:'+Cla+'\nTTL:'+str(ttl)+'\nRdlength:'+str(rdlen)+'\nAddress:'+rdip
    print(output)
    seraddr = (domain,rdip)
    return rdip,n+16,seraddr   

def anal_resp_auth(domain,data,n) :
    (offset,rdtype,rdclass,ttl,rdlen) = struct.unpack("!HHHLH",data[n:n+12])
    n=n+12
    i=n+1   #+1是为了去掉第一个长度单位的字节
    name = ''
    while True:
        d = data[i]
        if d == 0:
            break
        if d < 32:
            name = name + '.'      
        else:
            name = name + chr(d)  #将单个字节转换为字符
        i = i + 1
    i = i + 1 #去掉最后一个 \x00
    Type = 'NS'
    if rdtype == 2 :
        Type = 'NS'
    Cla = 'IN'
    if rdclass == 1 :
        Cla = 'IN'
    print('\nAuthentic:')
    output = 'Name:'+domain+'\nType:'+Type+'\nClass:'+Cla+'\nTTL:'+str(ttl)+'\nRdlength:'+str(rdlen)+'\nAddress:'+name
    print(output)
    return name,i

#解析answer
def anal_resp_ans(data,n,name):   #n为当前位置
    #(id, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
    #if answers > 0 :
    #    name,qtype,classify,nextbit=dnsquery(data,12)
    if (data[n+3] & 255) == 1 :     #判断type类型为‘A’
        (offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[n:n+16])
        rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
        return rdip,n+16   

#解析query段报文
def dnsquery(data,n):
    #解析域名
    i=n+1   #+1是为了去掉第一个长度单位的字节
    name = ''
    while True:
        d = data[i]
        if d == 0:
            break
        if d < 32:
            name = name + '.'      
        else:
            name = name + chr(d)  #将单个字节转换为字符
        i = i + 1
    #querybytes = data[n:i + 1]    #
    (qtype, classify) = struct.unpack('>HH', data[i + 1:i + 5])
    querylenend=i+5
    return name,qtype,classify,querylenend

##生成请求报文
def dnsrequest(data,rd):
    print(type(data),data,type(rd),rd)
    headerintid = random.randint(0,65535)
    header_id=struct.pack('!H',headerintid)
    header_flag=struct.pack('!BBHHHH',  rd, 0, 1, 0, 0, 0) #tp为0表示迭代，为1表示递归
    ##将域名转换为字节
    hoststr = ''.join(chr(len(x))+x for x in data.split('.'))
    hostbin=hoststr.encode()
    ##加上question尾部
    reqdata=header_id+header_flag+hostbin+b'\x00\x00\x01\x00\x01'
    return reqdata

def socket_client():
    defaddr = ('127.0.0.1', 6666)
    servise_name = 'local.dns'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    
    while 1:
        data = input('please input domain: ')
        data_domain =  data
        rd = input('请选择查询方式：0.迭代  1.递归  :')
        rd = int (rd)

        domains = data_domain.split('.')
        domainflag = 0
        for x in domains:
            if x == '' :
                domainflag = 1
                break
        if domainflag == 1 :
            output='\n服务器：'+servise_name+'\n'+'Addresses：'+defaddr[0]+'\n\n'
            output = output +'*** ' + servise_name + ' 找不到 '+data_domain + ': Unspecified error'
            print(output)
        elif len(domains) == 1 :
            output='\n服务器：'+servise_name+'\n'+'Addresses：'+defaddr[0]+'\n\n'
            output = output +'*** ' + servise_name + ' 找不到 '+data_domain + ': Non-existent domain'
            print(output)
        else :
            reqdata = dnsrequest(data,rd)
            print(reqdata)
            s.sendto(reqdata,defaddr)
            #接受回复
            print('已对',defaddr,'发送')
            serviceNP = []
            serviceNP.append(('local.dns','127.0.0.1'))
            sendnum = 1  ##记录发送报文个数
            while True :
                data, addr = s.recvfrom(1024)
                if data[3] & (1<<7) :
                    print('收到servise',addr,'响应数据')
                    ##解析header
                    (headerid, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
                    ##解析query
                    name,qtype,classify,nbit=dnsquery(data,12)

                    if answers > 0:
                        ##如果answer不等于0 说明已经找到对应的ip地址 如果三者都为0 说明找不到
                        hostip=[]
                        while answers:
                            ##解析answers
                            rdip,nbit=anal_resp_ans(data,nbit,name)
                            hostip.append(rdip)
                            answers=answers-1
                        servise_name = 'local.dns'
                        for x in serviceNP:
                            if x[1] == addr[0]:
                                servise_name = x[0]
                                break
                        output='\n服务器：'+servise_name+'\n'+'Addresses：'+addr[0]+'\n\n'
                        output = output +'名称：' + name + '\nAddresses：'
                        for x in hostip:
                            output =output + x + '\n\t'
                        print(output)
                        sendnum = sendnum -1
                        if sendnum == 0:
                            break 
                    elif (answers + author + addition == 0) & (rd == 1) :
                        output='\n服务器：loc_servise.dns\n'+'Addresses：'+addr[1]+'\n\n'
                        output = output +'名称：' + name + '\nAddresses：Unknow'
                        print(output)
                        break
                    elif (answers + author + addition == 0) & (rd == 0) :
                        for x in serviceNP:
                            if x[1] == addr[0]:
                                servise_name = x[0]
                                break
                        print('服务器:',servise_name,'  缓存表无此域名IP！')
                        getnewip = input('请输入查询服务器：')
                        if getnewip == 'exit':
                            output = '服务器：UnKnow\n'+'Addresses：Unknow\n\n'+'名称：'+name+'\nAddresses：Unknow'
                            print(output)
                            break
                        getport = get_port(getnewip)
                        end = 0
                        while getport == 0 :
                            getnewip = input('无法连接该服务器，请重新输入查询服务器：')
                            if getnewip == 'exit':
                                end = 1
                                break
                            getport = get_port(getnewip)
                        if end :
                            break
                        reqaddr = (getnewip,int(getport))
                        NandIP = get_ser_name(getnewip)
                        serviceNP.append(NandIP)
                        s.sendto(reqdata,reqaddr)
                        #sendnum = sendnum + 1
                    elif (author > 0) & (addition > 0) :
                        outbasicdata(headerid,flags,quests,answers,author,addition)
                        authornams=[]
                        while author :
                            anname , nbit =anal_resp_auth(data_domain,data,nbit)
                            authornams.append(anname)
                            author=author-1
                        addiip=[]
                        i = 0
                        while addition :
                            getip , nbit , seraddr = anal_resp_addi(authornams[i],data,nbit)
                            addiip.append(getip)
                            i = i +1
                            addition=addition-1
                            serviceNP.append(seraddr)
                        sendnum = sendnum -1  ###
                        nextstep = input('迭代确认下一步（任意键+回车）')
                        ipnum=len(addiip)
                        i=0
                        while ipnum :
                            req_port=get_port(addiip[i])
                            if req_port != 0:   #判断对应地址的port是否存在
                                req_addr = (addiip[i],req_port)
                                s.sendto(reqdata,req_addr)
                                sendnum = sendnum +1   ###
                            i = i + 1
                            ipnum = ipnum - 1
                        print('发送完毕 Waiting msg...')
                else :
                    pass  
    s.close()
 
 
if __name__ == '__main__':
    socket_client()