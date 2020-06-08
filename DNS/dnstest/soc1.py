from tkinter.simpledialog import *

def xz():
    s='123'
    lb.config(text=s)
    s=askstring('请输入','请输入一串文字')
    print(s)
    lb.config(text=s)

root = Tk()

lb = Label(root,text='')
lb.pack()
btn=Button(root,text='弹出输入对话框',command=xz)
btn.pack()
root.mainloop()
