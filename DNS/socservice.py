import socket
import time
import sys
import json
import random
import struct


def find_in_file(domain,data,rd):
    ##打开缓存文件查找
    flag = 0
    jsons = []
    fopen = open("D:\VS code\.vscode\DNS\soc_loc.txt",'r')
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
    print('len-s:',len(s))
    hostip =  struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
    #合并所有字节并返回
    respdata = respdata + anspartdata + hostip
    print(respdata)
    return respdata

## 根据ip地址找到对应的port
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

###接析addition段内容
def anal_resp_addi(data,n):
    (offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[n:n+16])
    rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
    return rdip,n+16    

###解析authentic段内容
def anal_resp_auth(data,n) :
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
    return name,i

### 保存查找内容到缓存中
def savedata(name,rdtype,rrclass,ttl,rdlength,rdata):
    dict={"name":None ,"type":None,"rrclass":None,"ttl":None,"rdlength":None,"rdata":None}

    dict['name']=name
    dict['type']=rdtype
    dict['rrclass']=rrclass
    dict['ttl']=ttl
    dict['rdlength']=rdlength
    dict['rdata']=rdata

    string=json.dumps(dict,ensure_ascii=False)+'\n'
    fo = open("D:\VS code\.vscode\DNS\soc_loc.txt", "a+")
    if fo.write(string):
        print("已添加至缓存文件夹...")
    fo.close()

    return 0

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

#解析answer
def anal_resp_ans(data,n,name):   #n为当前位置
    #(id, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
    #if answers > 0 :
    #    name,qtype,classify,nextbit=dnsquery(data,12)
    if (data[n+3] & 255) == 1 :     #判断type类型为‘A’
        (offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[n:n+16])
        rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
        ##存入缓存文件
        savedata(str(name),str(rdtype),str(rdclass),str(ttl),str(rdlen),rdip)
        return n+16       


##生成请求报文
def dnsrequest(data,tp):
    print(type(data),data,type(tp),tp)
    headerintid = random.randint(0,65535)
    header_id=struct.pack('!H',headerintid)
    header_flag=struct.pack('!BBHHHH',  tp, 0, 1, 0, 0, 0) #tp为0表示迭代，为1表示递归
    ##将域名转换为字节
    hoststr = ''.join(chr(len(x))+x for x in data.split('.'))
    hostbin=hoststr.encode()
    reqdata=header_id+header_flag+hostbin+b'\x00\x00\x01\x00\x01'
    print(reqdata)
    return reqdata

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

def socket_service():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 防止socket server重启后端口被占用（socket.error: [Errno 98] Address already in use）
        #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        loc_addr='127.0.0.1'
        loc_port=6666
        s.bind((loc_addr, loc_port))
        #s.listen(10)
    except socket.error as msg:
        print(msg)
        sys.exit(1)
    print('here is loc-servise(',loc_addr,loc_port,') and Waiting msg...')
 
    while 1:
        data, addr = s.recvfrom(1024)
        time.sleep(1)
        print('收到servise',addr,'请求数据')
        rm_data = data  ##用作头部生成
        #########第一次解析 
        
        ##解析header
        (id, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
        if flags & 256 == 256 :
            rd = 1
        else :
            rd = 0
        print(' rd: ',rd)
        ##解析query
        domain,qtype,classify,nbit=dnsquery(data,12)

        flag=0
        ###调用文件查找函数
        respdata,flag = find_in_file(domain,data,rd)
        if flag == 1 :
            print('在文件中找到匹配的了')
            s.sendto(respdata,addr)
        ## 根据flag 判断能否从缓存表找到ip地址 为0说明每找到 以下是没有找到
        else:
            print('没有没有在文件中找到匹配的')
            if rd == 0 :  #迭代方式
                respdata = dnsrespose_no(data,rd)
                s.sendto(respdata,addr)
                print('迭代方式的0回复已经返回',addr)
            else :  ##递归模式
                rm_addr=addr
                send_num = 0
                ####伏笔
                reqaddr_ip=input('req_Adrresses:') ##自己输入请求服务器
                reqaddr_port=get_port(reqaddr_ip)
                while reqaddr_port == 0 :
                        reqaddr_ip = input('无法连接该服务器，请重新输入req_Adrresses：')
                        reqaddr_port = get_port(reqaddr_ip)
                reqaddr_port=int(reqaddr_port)  #port需要 int 型
                s.sendto(data,(str(reqaddr_ip),reqaddr_port))
                send_num = send_num + 1
                ##接受响应报文，可设置while循环判断
                while True :
                    data, addr = s.recvfrom(1024)   ##更新data,addr
                    if data[3] & (1<<7) :
                        print('收到servise',addr,'响应数据')
                        ##############多次解析了 data addr值不断改变
                        ##解析header
                        (id, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
                        ##解析query
                        name,qtype,classify,nbit=dnsquery(data,12)

                        if answers > 0 :
                            ##如果answer不等于0 说明已经找到对应的ip地址
                            while answers:
                                ##解析answers 并保存缓存
                                nbit=anal_resp_ans(data,nbit,name)
                                #hostip.append(rdip)
                                answers=answers-1
                            send_num = send_num -1
                            if send_num == 0:
                                ##调用文件查找函数
                                respdata,fg = find_in_file(domain,rm_data,rd)  #这里的必须用rm_data
                                s.sendto(respdata,rm_addr)
                                break
                        elif answers + author + addition == 0 :
                            ### 如果三者都为0 说明找不到
                            send_num = send_num -1
                        elif (author > 0) & (addition > 0) :
                            authornams=[]
                            while author :
                                anname , nbit =anal_resp_auth(data,nbit)
                                authornams.append(anname)
                                author=author-1
                            addiip=[]
                            while addition :
                                getip , nbit = anal_resp_addi(data,nbit)
                                addiip.append(getip)
                                addition=addition-1

                            send_num = send_num - 1  #及时收到的报文没有answer 也要-1

                            iplen=len(addiip)
                            i=0
                            while iplen :
                                req_port=get_port(addiip[i])
                                if req_port != 0:   #判断对应地址的port是否存在 为0不存在
                                    req_addr=(addiip[i],req_port)
                                    print('对服务器',req_addr,'发送数据')
                                    s.sendto(rm_data,req_addr)   #rm_data为第一次请求报文数据
                                    send_num = send_num + 1
                                i = i + 1
                                iplen = iplen - 1
                            print('递归模型：发送完毕 Waiting msg...')
                    else :
                        pass 

                #a=input()
        print('发送完毕 \n here is loc-servise(',loc_addr,loc_port,') andWaiting msg...')

    s.close()

 
if __name__ == '__main__':
    socket_service()