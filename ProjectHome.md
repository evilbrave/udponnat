# UDPonNAT [[中文版](http://code.google.com/p/udponnat/wiki/What_is_UDPonNAT_CN)] #

## What's UDPonNAT: ##

> UDPonNAT is a PROXY for UDP application. With UDPonNAT, you can make your UDP application server to provide service behind the NAT device. UDPonNAT is writen in Python and published under the GPLv3. UDPonNAT is a cross-platform software, it can run on many OS, such as Windows/Linux/Unix.

## What's the UDPonNAT used for: ##

> The most UDP application have the following work mode:

> ![http://udponnat.googlecode.com/files/normal_udp_top.png](http://udponnat.googlecode.com/files/normal_udp_top.png)

> After the UDP application server is launched, it will bind a solid UDP Port and then wait for coming UDP packets and do some replies. If the server has a real IP address, it can be accessed from anywhere of the internet. However, there are some server only has a private IP address, only the host in the same LAN can access it. What can you do if you want any client in the internet access it? Maybe you should try UDPonNAT.

> With UDPonNAT, you can make your UDP application server to provide service even if your server host hasn't got a real IP.

> ![http://udponnat.googlecode.com/files/nat_udp_top.png](http://udponnat.googlecode.com/files/nat_udp_top.png)

> The above picture means that your UDP application client can't access the UDP application server directly because of the NAT device, but with UDPonNAT you could do it.

## How to use UDPonNAT: ##

> I'll take OpenVPN as a UDP application example to illustrate how to use UDPonNAT. Assuming that you want access to your office computer C from your home computer H. C and H both are using the Windows system and you've already known how to setup OpenVPN server/client respectly on C/H.

> Note that all the programs mentioned in this article should be launched in command line.

  * 1, Download the UDPonNAT's package for Windows from http://code.google.com/p/udponnat/downloads/list and then decompress it to anywhere of your harddisk, like "C:\UDPonNAT".

  * 2, Try to get the type of the network of C and H in. You can get it by run the stunclient.exe in UDPonNAT package. Normally the outputs are as below:
> > NET TYPE: Port Restricted Cone NAT(5)
    * a) The number in the brackets indicates the type of the network and you should remember it for later use.
    * b) As we know, not all NAT device can be penetrated. UDPonNAT classified all network types into 9. Each one of them except type 8 has the possiblity to be penetrated. The less the type number is the more it likely to be penetrated. And it's almost definitely can be penetrated if the type number of anyone of the 2 ends is less or equal than 5.


> The outputs like "UDP is blocked or The STUN server(stun.iptel.org: 3478) is NOT available." indicates that it failed to get network type. There are 2 possible reasons:
    * a) The UDP communication is totally disallowed in the network of your computer in and UDPonNAT can't work.
    * b) Maybe the specified STUN server is broken or turned off. In this case, you should simply choose another STUN server by modify the stun\_server in stun\_server.conf. Here is a list of free STUN servers.

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

  * 3, Because of the UDPonNAT uses GTalk server to exchange information when it try to establish new UDP connection, you need to register 2 GTalk accounts. For example, i register uServer@gmail.com and uClient@gmail.com. Note that after you register them you must use GTalk to logon and add them each other as a friend, otherwise you couldn’t send or receive any message between them.

  * 4, Setup UDPonNAT server. UDPonNAT server is running on the host C. It receives the data from UDPonNAT client and then forwards them to the UDP application server (here is OpenVPN). You can modify the server.conf for your situation.
    * a) "to" indicates the address of the UDP application server listened on. for example, OpenVPN's is "127.0.0.1:1194".
    * b) "net\_type" indicates the network type of host C in, which you've got at phase 2.
    * c) "stun\_server" indicates the the address of the STUN server.
    * d) "GTalk\_server" indicates the address of the GTalk server.
    * e) "i" indicates the GTalk user who uses in the UDPonNAT server end, mine is "uServer".
    * f) "allowed\_user" indicates the GTalk user who is allowed to connect the UDPonNAT server, mine is "uClient".

  * 5, Setup UDPonNAT client. UDPonNAT client is running on the host H. It bind a solid port and receives the data from UDP application client (here is OpenVPN) and then forwards them to the UDPonNAT server on the host C. You can modify the client.conf for your situation too.
    * a) "listen" indicates the address of the UDPonNAT client listened on. Note that you must tell your UDP application client this is the UDP application server's address. In other words, the UDP application client should send data to here instead of to the real UDP application server.
    * b) "net\_type" indicates the network type of host H in, which you've got at phase 2.
    * c) "stun\_server" indicates the the address of the STUN server.
    * d) "GTalk\_server" indicates the address of the GTalk server.
    * e) "i" indicates the GTalk user who uses in the UDPonNAT client end, mine is "uClient".
    * f) "server\_user" indicates the GTalk user who uses in the UDPonNAT server end.

  * 6, Launch all program.
    * a) Launch the OpenVPN server on C.
    * b) Launch the UDPonNAT server "server.exe". After it is running, it will ask you for the password for the specified GTalk user. Wait for several seconds, you could see the specified user is online from GTalk.
    * c) Go home and launch UDPonNAT client "client.exe" in H. Input the password and wait for several seconds, UDPonNAT client will tell you whether the UDP connection is established or not.
    * d) If the connection is established, you can launch the UDP application client. But don't forget to change the OpenVPN's server address to the "listen" of the client.conf.

## Others: ##

> Maybe this article is not very clear. If you have any question about UDPonNAT, please contact me. My EMail is dugang@188.com.

> Thanks!