import struct
import os
import binascii
import json


dict={"name":None ,"type":None,"rrclass":None,"ttl":None,"rdlength":None,"rdata":None}

dict['name']='www.test.com'
dict['type']='1'
dict['rrclass']='1'
dict['ttl']='4252'
dict['rdlength']='10'
dict['rdata']='124.178.25.153'


string=json.dumps(dict,ensure_ascii=False)+'\n'
print(string)
print(type(string))
fo = open("D:\VS code\.vscode\DNS\soc_test_com.txt", "a+")
print(fo.name)
if fo.write(string):
   # fo.write('\r\n')
    print("ok!")
fo.close()
'''
fopen=open("D:\VS code\.vscode\DNS\soc_loc.txt")
for line in fopen:
    if line != '\n':
        print (line)
        #print(type(line))
        #jsObj = json.loads(line)
        #print(jsObj)
        #print(type(jsObj),type(jsObj['name']))
fopen.close()
'''

#jsObj=[]
#jsObj = json.load(open(filename))
#print(jsObj)
#print(type(jsObj))


