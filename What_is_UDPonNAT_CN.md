# UDPonNAT #
## UDPonNAT是什么： ##
> UDPonNAT是一个UDP代理，它能让普通的UDP应用跨越NAT网络设备。UDPonNAT使用Python编写，遵守GPL协议发布，可运行的平台包括Windows/Linux/Unix等。

## UDPonNAT有什么用途： ##
> 普通的UDP应用大多具有如下的工作方式：

> ![http://udponnat.googlecode.com/files/normal_udp_top.png](http://udponnat.googlecode.com/files/normal_udp_top.png)

> Server运行后，UDP服务被绑定到一个固定的IP:Port上，等待来自Client的UDP数据包并响应。如果Server具有真实的IP地址，则Client可以从Internet的任意位置访问Server提供的服务。但现实中还有一些情况，比如作为Server所在的主机只有一个局域网内部IP（该主机如果要访问Internet资源需要通过NAT设备），这时Server仅能让同一个局域网内的Client访问，如果想让Internet上的Client也能访问该Server，如何做呢，可以试试UDPonNAT。

> UDPonNAT能让没有真实独立IP的UDP Server透过NAT设备对外提供服务，如图：

> ![http://udponnat.googlecode.com/files/nat_udp_top.png](http://udponnat.googlecode.com/files/nat_udp_top.png)

> 该图的意思是，因为NAT设备的存在，Internet上的Client并不能直接访问到局域网内的Server，但通过UDPonNAT代理软件就可以。

## 如何使用UDPonNAT： ##
> 这里以一个UDP的应用OpenVPN为例说明如何使用UDPonNAT。这里假设你需要从家里的电脑H访问公司的电脑C，而C处于公司的NAT设备（比如防火墙）之后，C和H都运行的是Windows操作系统。并且您已经知道如何分别在C和H上配置OpenVPN服务端和客户端。

> 注意：本文中的所有程序需要在windows命令行方式下运行。

  * 1， 下载并安装UDPonNAT。从http://code.google.com/p/udponnat/downloads/list 下载最新的UDPonNAT for windows软件包，解压到磁盘的任意位置，比如C:\UDPonNAT。

  * 2， 确认C与H所在的网络环境。通过在C和H上分别运行UDPonNAT目录下的stunclient.exe可以得到当前网络类型。一般该命令输出如下：
> > NET TYPE: Port Restricted Cone NAT(5)
    * a)  括号内的数字代表的是具体网络类型，这个数字后面将会用到。
    * b)  我们知道，UDP穿透是和待通信两端的网络类型密切相关的，并非所有网络都可穿透。UDPonNAT将网络分为9种，除去类型8不能通信外，其它都有可能通信，数字越小可能性越高，一般来说，只要通信两端中有一端网络类型小于等于5则网络就可能穿透。

> 如果运行结果类似于“UDP is blocked or The STUN server(stun.iptel.org: 3478) is NOT available.”，说明探测网络类型失败，有两种可能原因：
    * a)  主机所在网络不允许UDP通信，这种情况UDPonNAT是无法工作的。
    * b)  UDPonNAT使用的开放STUN server可能坏掉了，您可以通过修改stunclient.conf文件中的stun\_server项来换一个其他STUN server再试试，以下是一个可用的STUN server列表：

```
            stun01.sipphone.com
            stun.ekiga.net
            stun.fwdnet.net
            stun.ideasip.com
            stun.iptel.org
            stun.rixtelecom.se
            stun.schlund.de
            stunserver.org
            stun.softjoys.com
            stun.voiparound.com
            stun.voipbuster.com
            stun.voipstunt.com
            stun.voxgratia.org
            stun.xten.com
```

> 注意：对于教育网的用户来说，因为免费的STUN server大多是国际流量，教育网内可能无法直接访问，因而UDPonNAT包中提供了一个替代程序：cernet.exe，通过运行它你也可以获得当前网络类型，但没有stunclient.exe的准确性高。

  * 3， 注册两个GMail账号，这是因为UDPonNAT在建立UDP连接过程中需要使用GTalk做辅助。比如uServer@GMail.com/uClient@GMail.com，注意注册账号后还需要使用GTalk软件分别以两个账号登入并且互相加为好友，确认互相可收发消息。

  * 4， 配置UDPonNAT Server端。UDPonNAT Server端运行在主机C上，它等待来自指定UDPonNAT Client端的数据并将其转发到实际的UDP应用Server端口上，我们这里的UDP应用Server是OpenVPN Server。通过正确填写UDPonNAT目录下的server.conf文件来进行Server端配置。
    * a)  to表示应用Server的UDP端口，比如OpenVPN监听的是“127.0.0.1:1194”。
    * b)  net\_type是第2步中获取的网络类型数字。
    * c)  stun\_server如果是教育网，请使用“stun.l.google.com:19302”。
    * d)  GTalk\_server一般保留不变即可。
    * e)  i表示Server端使用的GTalk用户，uServer。
    * f)  allowed\_user表示允许哪个用户从UDPonNAT Client端接入，uClient。

  * 5， 配置UDPonNAT Client端。UDPonNAT Client端运行在主机H上，它从指定的端口等待UDP应用Client发出的数据包并将这些数据包穿透NAT设备转发给C上的UDPonNAT Server，我们这里的UDP应用Client是OpenVPN Client。同样需要填写配置文件client.conf：
    * a)  listen表示UDPonNAT的监听端口。需要注意的是UDP应用Client（OpenVPN）也需要将服务器的地址设为这个端口，即将发往应用服务器的数据发送到这里。
    * b)  net\_type是第2步中获取的网络类型数字。
    * c)  stun\_server如果是教育网，请使用“stun.l.google.com:19302”。
    * d)  GTalk\_server一般保留不变即可。
    * e)  i表示Client端使用的GTalk用户，uClient。
    * f)  server\_user表示UDPonNAT Server用户，只有该用户所在的服务器才能与之通信。

  * 6， 启动各个软件。
    * a)  启动主机C上的UDP应用软件OpenVPN Server。
    * b)  启动主机C上的UDPonNAT Server，只要在UDPonNAT目录下运行server.exe并且按提示输入密码即可。等待数秒后您可以使用uClient用户登入到GTalk，这时您应该看到uServer用户已在线。
    * c)  回家，打开主机H，运行UDPonNAT Client，同样，只须在UDPonNAT目录下运行client.exe并且按提示输入密码即可。等待数秒后，UDPonNAT将提示您连接是否建立或者失败。
    * d)  如连接成功建立，这时启动UDP应用Client（OpenVPN Client），不过记得将OpenVPN的服务器地址设成client.conf中的listen地址。

## 后记： ##
> UDPonNAT是我在08年9月即完成的，期间一直在搭配OpenVPN使用，因为没能写文档的原因而拖到了09年元旦才发出来。

> 我写的几个小软件基本上都是源于我自己的实际需要，比如stripcc是因为看C项目代码无法忍受太多的条件编译分支破坏思路，GAppProxy是因为我住在教育网环境内无法访问国际网络，而UDPonNAT也是因为我需要在家里登入到工作的电脑上。

> UDPonNAT的思路直接来源于我在08年5月写的一片文章《不需公网IP架设OpenVPN》，该文章里附带了一些python的实现脚本，但后来我发现很多朋友无法正确使用该脚本，其中也包括一些计算机基础很好的朋友，因而最终萌发了写一个类似功能的更高效更易配置的独立软件，这就是UDPonNAT。UDPonNAT使用GTalk替换了原来的GMail通信，让连接建立速度大大提高，并且支持网络的类型也更多。

> 一段仅供自己使用的代码和一个功能类似的小的开源软件在我实际体会上还是有着很大的差别，主要是体现在开发工作量和使用体验上。发布UDPonNAT的目的是希望它能对其他人同样有用。

> 这段文档也许不够清楚，如果您在使用过程中遇到了任何问题，欢迎发邮件和我交流，dugang@188.com。

> 关于STUN协议，参考：http://blog.chinaunix.net/u/10449/showart.php?id=1146001

> 关于GTalk通信，参考：http://blog.chinaunix.net/u/10449/showart.php?id=1147690

> 关于OpenVPN穿越NAT，参考：http://blog.chinaunix.net/u/10449/showart.php?id=688463

> 更多的参考文章见UDPonNAT的docs目录。

> 谢谢！