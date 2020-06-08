import socket
from tkinter import *

domians = [] #全局变量，记录输入域名

def senddata():
    getdata= ent1.get()
    addinfor(getdata)
    sock.sendtodata(getdata,0)
    ent1.config(state=DISABLED)
    sock.recvfromdata()

def addinfor(table):
    text.config(state=NORMAL)
    text.insert(END,table)
    text.insert(END,'\n')
    text.config(state=DISABLED)

def change(data):
    data = data + 10
    return data

class Client:
    def __init__(self):
        self.name = 'Client'
        self.host = '127.0.0.1'
        self.port = 9090
        self.addr = ('127.0.0.1',9090)

        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        except socket.error as msg:
            print(msg)
            sys.exit(1)
        #创建发送消息和发送目标

    def sendtodata(self,data,rd):
        print(data)
        print(rd)
        chanrd = change(rd)
        print(chanrd)
        msg = data
        print(type(msg),msg)
        msg=msg.encode()
        self.s.sendto(msg,self.addr)

    
    def recvfromdata(self):
        #接受回复
        rst = self.s.recvfrom(1024)
        print(rst)
        print('client getdata')
    

    #关闭链接
    def closestoc(self):
        self.s.close()

if __name__ == '__main__':
    sock = Client()
    root = Tk()
    root.geometry('650x700')
    root.title('客户端')
    #s1
    text = Text(root,font=('华文新魏',14))
    text.place(x=0,y=45,height=650,width=650)
    text.config(state=DISABLED)

    u = StringVar()
    ent1 = Entry(root, textvariable=u)
    ent1.place(x=0,y=10,height=25,width=450)
    b = Button(root,text='开始',command=senddata)
    b.place(x=500,y=10,height=25,width=50)


root.mainloop()