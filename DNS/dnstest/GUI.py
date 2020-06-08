from tkinter import *
import time
import datetime

inputdata = ''
chosicrd = 1

def cleartext():
    ent1.delete(0, END)

def test():
    getdata= ent1.get()
    print(type(getdata),getdata)
    inputdata = getdata
    return inputdata


def test_fun(self):
    test()

root=Tk()
root.geometry('650x700')

u = StringVar()
ent1 = Entry(root, textvariable=u)
ent1.place(x=0,y=10,height=25,width=450)
b = Button(root,text='开始',command=test)
b.place(x=500,y=10,height=25,width=50)
#ent1.bind("<Return>", test_fun)
db = Button(root,text='清空',command=cleartext)
db.place(x=570,y=10,height=25,width=50)


string = 'askjasdg\n 566465gs  654622 \n sdas gas'
text = Text(root)
text.config(font=('Arial',14))
text.place(x=0,y=45,height=650,width=650)
#text.config(state=NORMAL)
text.insert(END,string)
text.config(state=DISABLED)

root.mainloop()
