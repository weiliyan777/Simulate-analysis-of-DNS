import socket
import random
import struct
from tkinter import *
import tkinter.messagebox
from tkinter.simpledialog import *
import select

def outbasicdata(ip,flags,quests,answers,author,addition): #迭代中间过程查询信息输出
    print('Transaction ID: ',hex(ip))
    info = 'Transaction ID: ' + str(hex(ip))
    addinfor(info)
    print('Flags: ',hex(flags),' Standard query')
    info = 'Flags: ' + str(hex(flags)) + ' Standard query' 
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
    info = '  ' + str(qr) + '... .... .... = Response: Message is a query'
    addinfor(info)
    print(info)
    info = '  .' + stropcode + '... .... .... = Opcode: Standard query (' + str(opcode) + ')'
    addinfor(info)
    print(info)
    info = '  .... ..' + str(tc) + '. .... .... = Truncated: Message is not truncated'
    addinfor(info)
    print(info)
    info = '  .... ...' + str(rd) + ' .... .... = Recursion desired: Dont do query recursively'
    addinfor(info)
    print(info)
    info = '  .... .... .' + str(Z) + '.. .... = Z: reserved (' + str(Z) + ')'
    addinfor(info)
    print(info)
    info = '  .... .... ...'+ str(nona) + ' .... = Non-authenticated data: Unacceptable'
    addinfor(info)
    print(info)
    info = 'Questions:' + str(quests)
    addinfor(info)
    print(info)
    info = 'Answer RRs:' + str(answers)
    addinfor(info)
    print(info)
    info = 'Authority RRs:' + str(author)
    addinfor(info)
    print(info)
    info = 'Additional RRs:' + str(addition)
    addinfor(info)
    print(info)

def get_ser_name(ip):  #获得ip地址对应的服务器名
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

def get_port(ip): #获得ip地址对应的端口
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

def anal_resp_addi(domain,data,n): #分析响应报文的Additional段
    (offset,rdtype,rdclass,ttl,rdlen,ip1,ip2,ip3,ip4) = struct.unpack("!HHHLHBBBB",data[n:n+16])
    rdip=str(ip1)+'.'+str(ip2)+'.'+str(ip3)+'.'+str(ip4)
    Type = 'A'
    if rdtype == 1 :
        Type = 'A'
    Cla = 'IN'
    if rdclass == 1 :
        Cla = 'IN'
    print('\nAddition:')
    addinfor('\nAddition:')
    output = 'Name:'+domain+'\nType:'+Type+'\nClass:'+Cla+'\nTTL:'+str(ttl)+'\nRdlength:'+str(rdlen)+'\nAddress:'+rdip
    addinfor(output)
    print(output)
    seraddr = (domain,rdip)
    return rdip,n+16,seraddr   

def anal_resp_auth(domain,data,n) : #分析响应报文的Authority段
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
    addinfor('\nAuthentic:')
    output = 'Name:'+domain+'\nType:'+Type+'\nClass:'+Cla+'\nTTL:'+str(ttl)+'\nRdlength:'+str(rdlen)+'\nAddress:'+name
    print(output)
    addinfor(output)
    return name,i

#解析answer
def anal_resp_ans(data,n,name):   #n为当前位置
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
    #print(type(data),data,type(rd),rd)
    headerintid = random.randint(0,65535)
    header_id=struct.pack('!H',headerintid)
    header_flag=struct.pack('!BBHHHH',  rd, 0, 1, 0, 0, 0) #tp为0表示迭代，为1表示递归
    ##将域名转换为字节
    hoststr = ''.join(chr(len(x))+x for x in data.split('.'))
    hostbin=hoststr.encode()
    ##加上question尾部
    reqdata=header_id+header_flag+hostbin+b'\x00\x00\x01\x00\x01'
    return reqdata

def deleteentry():   #清空文本框
    while len(endfind):
        endfind.pop()
    ent1.config(state=NORMAL)
    ent1.delete(0,END)

def senddata():
    #获得查询内容
    data = ent1.get()
    ent1.config(state=DISABLED)
    rd = var.get()

    #判断查询内容格式是否符合
    data_domain = data
    sock.data_domain = data_domain
    domains = data_domain.split('.')
    domainflag = 0
    for x in domains:
        if x == '' :
            domainflag = 1
            break
    if domainflag == 1 :
        output='\n服务器：'+servise_name+'\n'+'Addresses：'+defaddr[0]+'\n\n'
        output = output +'*** ' + servise_name + ' 找不到 '+data_domain + ': Unspecified error'
        addinfor(output)
        deleteentry()
    elif len(domains) == 1 :
        output='\n服务器：'+servise_name+'\n'+'Addresses：'+defaddr[0]+'\n\n'
        output = output +'*** ' + servise_name + ' 找不到 '+data_domain + ': Non-existent domain'
        addinfor(output)
        deleteentry()
    else :  #符合
        reqdata = dnsrequest(data,rd)  #调用请求报文生成函数获得请求报文
        print(reqdata)
        sock.sendtodata(reqdata,defaddr)  #向本地服务器发送请求报文
        info = '已对('+defaddr[0]+','+str(defaddr[1])+')发送请求报文'
        addinfor(info)
        serviceNP.append(('local.dns','127.0.0.1'))  #存储记录服务器以及其地址
        sendnum = 1
        sendcount.append(sendnum)  
        endfind.append(1)
        root.after(1000,revcdata()) #进入等待循环

def addinfor(table):  #输出信息到窗口
    text.config(state=NORMAL)
    text.insert(END,table)
    text.insert(END,'\n')
    text.config(state=DISABLED)


def revcdata():    #判断是否接收响应报文，并查看缓冲区有无内容
    if len(endfind) > 0:
        infds,outfds,errfds = select.select([sock.s],[],[sock.s],0.05)
        if len(infds):
            sock.recvfromdata()
        if len(errfds):
            print("\rProblem occurred;exiting.")
            sys.exit(0)
        ####循环
        root.after(2000,revcdata())
    root.update_idletasks()
    root.update()
    

class Client:
    def __init__(self):
        self.name = 'Client'
        self.host = '127.0.0.1'
        self.port = 6666
        self.addr = ('127.0.0.1',6666)
        self.s = None
        self.reqdata = None
        self.data_domain = None

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        

    def sendtodata(self,data,addr):
        print(data)
        self.reqdata = data
        self.s.sendto(data,addr)

    def recvfromdata(self):
        #接受回复
        data , addr = self.s.recvfrom(1024)
        if data[3] & (1<<7) :
            print('收到servise',addr,'响应数据')
            ##解析header
            (headerid, flags, quests, answers, author, addition) = struct.unpack('!HHHHHH', data[0:12])
            ###求查询类型
            if flags & 256 == 256 :
                rd = 1
            else :
                rd = 0
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
                addinfor(output)
                sendnum = sendcount.pop()
                sendnum = sendnum - 1
                if sendnum == 0:
                    deleteentry()
                else :
                    sendcount.append(sendnum)
            ###递归查询返回结果
            elif (answers + author + addition == 0) & (rd == 1) :
                output='\n服务器：loc_servise.dns\n'+'Addresses：'+addr[0]+'\n\n'
                output = output +'名称：' + name + '\nAddresses：Unknow'
                addinfor(output)
                deleteentry()
            ####迭代查询返回结果
            elif (answers + author + addition == 0) & (rd == 0) :
                for x in serviceNP:
                    if x[1] == addr[0]:
                        servise_name = x[0]
                        break
                info = '服务器:' + servise_name +'  缓存表无此域名IP！\n'
                addinfor(info)
                getnewip = ''
                getnewip=askstring('请输入','请输入新的地址')
                if getnewip == None:
                    output = '服务器：UnKnow\n'+'Addresses：Unknow\n\n'+'名称：'+name+'\nAddresses：Unknow\n'
                    addinfor(output)
                    deleteentry()
                else :
                    getport = get_port(getnewip)
                    end = 0
                    while getport == 0 :
                        getnewip=askstring('无法连接该服务器','请重新输入查询服务器:')
                        if getnewip == None:
                            end = 1
                            break
                        getport = get_port(getnewip)
                    if end :
                        deleteentry()
                    else :
                        reqaddr = (getnewip,int(getport))
                        NandIP = get_ser_name(getnewip)
                        serviceNP.append(NandIP)
                        self.s.sendto(self.reqdata,reqaddr)
                ####收到一次，发送一次，抵消sendnum
            ##返回NS域地址
            elif (author > 0) & (addition > 0) :
                outbasicdata(headerid,flags,quests,answers,author,addition)
                authornams=[]
                while author :
                    anname , nbit =anal_resp_auth(self.data_domain,data,nbit)
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
                
                sendnum = sendcount.pop()
                sendnum = sendnum -1  
                sendcount.append(sendnum)

                answer=tkinter.messagebox.askokcancel('请选择','是否进入下一步')
                if answer:
                    ipnum=len(addiip)
                    i=0
                    while ipnum :
                        req_port=get_port(addiip[i])
                        if req_port != 0:   #判断对应地址的port是否存在
                            req_addr = (addiip[i],req_port)
                            self.s.sendto(self.reqdata,req_addr)
                            ###更改发送个数
                            sendnum = sendcount.pop()
                            sendnum = sendnum +1   
                            sendcount.append(sendnum)
                        i = i + 1
                        ipnum = ipnum - 1
                    #info = '发送完毕 等待'
                    #addinfor(info)
                else :
                    output = '服务器：UnKnow\n'+'Addresses：Unknow\n\n'+'名称：'+name+'\nAddresses：Unknow'
                    addinfor(output)
                    deleteentry()
        else :
            pass
        
    #关闭链接
    def closestoc(self):
        self.s.close()

if __name__ == '__main__':
    servise_name = 'local.dns' #全局变量
    defaddr = ('127.0.0.1', 6666)
    serviceNP = []    #用于记录服务器域名以及地址
    sendcount = []    #用于记录发送请求的个数
    endfind = []      #用于记录等待接收响应报文的个数

    sock = Client()

    root = Tk()
    root.geometry('650x700')
    root.title('客户端')
    #text
    scroll = Scrollbar(root)
    scroll.place(x=630,y=45,height=650,width=20)
    text = Text(root,font=('华文新魏',14),yscrollcommand = scroll.set)
    text.place(x=0,y=45,height=650,width=630)
    text.config(state=DISABLED)
    scroll.config(command = text.yview)

    u = StringVar()
    ent1 = Entry(root, textvariable=u)
    ent1.place(x=0,y=5,height=30,width=450)

    b = Button(root,text='查找',command=senddata)
    b.place(x=585,y=10,height=25,width=45)
    var = IntVar()
    rd1 = Radiobutton(root,text="迭代",variable=var,value=0)
    rd1.place(x=465,y=12)

    rd2 = Radiobutton(root,text="递归",variable=var,value=1)
    rd2.place(x=515,y=12)

    root.mainloop()


