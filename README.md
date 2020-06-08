# Simulate-analysis-of-DNS
基于python Socket技术下的模拟DNS解析过程

运行环境：python 3

大致思想：里面进程模拟dns服务器，利用python的Socket技术在进程之间模拟dns解析的过程

文件描述：
客户端：client.py(带界面

本地服务器：service.py（带界面）

其他级别服务器：service_root.py、service_com.py、service_com2.py、service_testcom.py

codec.py：向缓存文件输入记录内容

put_NandIP.py：向记录着服务器名及地址文件输入记录内容

put_port.py：向记录着服务器地址及端口文件输入记录内容

viewfile.py：窗口查看文件

socclient.py ：不带界面的客户端，实现内容与client.py一致

socservice.py ：不带界面的本地服务器，实现service.py内容与一致

soc_X.txt：表示X服务器缓存

soc_X_ns.txt：表示X服务器NS域缓存

soc_NandIP.txt：服务器名及地址文件

soc_serv_port.txt：服务器地址及端口文件


dnstest文件夹内文件属于功能测试文件

注意事项！！！
运行时，需要运行client.py、service.py（或socclient.py、socservice.py ）、service_root.py、
service_com.py、service_com2.py、service_testcom.py

！！！记得修改每一个py文件内对应打开的txt文件对应的路径！！！

DNS解析的两种方式流程： https://www.jianshu.com/p/6b502d0f2ede
测试样例可根据上述网站了解流程过后，观察soc_X.txt文件自行测试
如输入 www.baidu.com 选择迭代方式，可得到输出
当出现弹框需求输出服务器地址时，可看soc_NandIP.txt文件查看现有的服务器，输入的服务器地址将作为新的查询服务器
（注意：当选择递归查询时，如本地服务器缓存无查询结果，一样需要输入新的服务器地址作为查询的服务器）



