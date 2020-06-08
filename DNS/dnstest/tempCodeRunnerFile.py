fopen=open("D:\VS code\.vscode\DNS\soc_loc.txt")
for line in fopen:
    if line != '\n':
        print (line)
        print(type(line))
        jsObj = json.loads(line)
        print(jsObj)
        print(type(jsObj),type(jsObj['name']))
        print(jsObj['ttl'].encode())
fopen.close()