from Tkinter import *

def getpwd():
    password = ''
    root = Tk()
    pwdbox = Entry(root, show = '*')
    def onpwdentry(evt):
         password = pwdbox.get()
         root.destroy()
    def onokclick():
         password = pwdbox.get()
         root.destroy()
    Label(root, text = 'Password').pack(side = 'top')

    pwdbox.pack(side = 'top')
    pwdbox.bind('<Return>', onpwdentry)
    Button(root, command=onokclick, text = 'OK').pack(side = 'top')

    root.mainloop()
    return password

getpwd()
