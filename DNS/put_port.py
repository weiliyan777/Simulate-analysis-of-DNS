import struct
import os
import binascii
import json

string ='127.0.0.5,7700'+'\n'
fo = open("D:\VS code\.vscode\DNS\soc_serv_port.txt", "a+")
#print(fo.name)
if fo.write(string):
   # fo.write('\r\n')
    print("ok!")
fo.close()

'''
fopen=open("D:\VS code\.vscode\DNS\soc_loc_port.txt",'r')
for line in fopen:
    if line != '\n':
        print (line)
        print(type(line))
        data=line.split(',')
        print(data)
fopen.close()
'''
