from tkinter import *
import time

###添加数据到界面去
def addinfor(data):
    text.config(state=NORMAL)
    text.insert(END,data)
    text.insert(END,'\n')
    text.config(state=DISABLED)

def recvdata2(num):
    info = '第' + str(num) + '次循环'
    addinfor(info)
    num = num + 1
    time.sleep(3)
    root.after(1000,recvdata2(num))


def recvdata1():
    info = '第一次循环'
    addinfor(info)
    root.after(1000,recvdata2(2))
    root.after(1000,recvdata1)

if __name__ == '__main__':
    print('start!')
    root = Tk()
    root.geometry('650x700')
    root.title('服务端')
    #text
    scroll = Scrollbar(root)
    scroll.place(x=630,y=0,height=700,width=20)
    text = Text(root,font=('华文新魏',14),yscrollcommand = scroll.set)
    text.place(x=0,y=0,height=700,width=630)
    text.config(state='disabled')
    scroll.config(command = text.yview)

    ##开始接收
    root.after(1000,recvdata1)


    root.mainloop()
