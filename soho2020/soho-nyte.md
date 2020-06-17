IoT Village SoHOpelessly Broken Write-Up

Courtesy of nyte

This entire CTF was hosted online. Usually, this event in in-person, with physical devices available to look at and ask questions about.

For this event, there are three subnets (192.168.10.0, 20.0, and 30.0) where any device in the 10 subnet can talk to the 20, and the 20 subnet can talk to the 30. Pivoting is necessary to reach the other networks, through ssh tunneling and proxychains. If you don&#39;t know how to do this, practice beforehand. Most devices seemed to allow gatewayports and tcpforwarding, so shouldn&#39;t have to modify any sshd config files on the fly.

Scans of two networks that were reached have been added to the end of the write-up. Unfortunately, I wasn&#39;t able to scan the third network, as I was focused on trying to continue capturing flags.

- 192.168.10.0 Network targets:
  - 10.4 – Seagate Device
    - Used enum4linux on target, discovered &quot;public&quot; writeable share.
    - Discovered vulnerable version of Samba
    - Used is\_known\_pipename exploit in MSF to gain access
  - 10.5 – Teramaster NAS
    - Also leveraged is\_known\_pipename
  - 10.6 – Asustor AS-602T
    - Appears to be vulnerable to this CVE: [https://blog.securityevaluators.com/terramaster-nas-vulnerabilities-discovered-and-exploited-b8e5243e7a63](https://blog.securityevaluators.com/terramaster-nas-vulnerabilities-discovered-and-exploited-b8e5243e7a63)
    - May have used is\_known\_pipename to gain access
  - 10.7 – GeoVision GV-SNVR0811
    - Known directory traversal vulnerability
    - Didn&#39;t seem to work for me (though I used same exploit that worked before)
    - Instead, just found flag here: [https://blog.welcomethrill.house/2018/08/def-con-26-iot-village-sohopelessly.html](https://blog.welcomethrill.house/2018/08/def-con-26-iot-village-sohopelessly.html)
    - Root password is actually empty, so just submit hash for points.
  - 10.18 – Buffalo TeraStation
    - Appears to be vulnerable to known CVE. Used json found here to open Telnet: [https://blog.securityevaluators.com/buffalo-terastation-ts5600d1206-nas-cve-disclosure-ab5d159f036d](https://blog.securityevaluators.com/buffalo-terastation-ts5600d1206-nas-cve-disclosure-ab5d159f036d)
    - Once enabled, Telnet had no credentials.
  - 10. 8 – Zyxel NAS
    - We know it&#39;s this vulnerability, but couldn&#39;t get it to fire: [https://blog.securityevaluators.com/ise-labs-finds-vulnerabilities-in-zyxel-nsa325-945481a699b8](https://blog.securityevaluators.com/ise-labs-finds-vulnerabilities-in-zyxel-nsa325-945481a699b8)
    - Worked for someone on my team before at BSides DC.
- 192.168.20.0 Network Targets:
  - 20.5 – NUUO
    - Tried a ton of exploits:
      - auxiliary/admin/http/nuuo\_nvrmini\_reset -- Seemed to work?
      - exploit/linux/http/nuuo\_nvrmini\_auth\_rce -- Failed Auth
      - exploit/linux/http/nuuo\_nvrmini\_unauth\_rce -- Doesn&#39;t seem to execute
      - multi/http/nuuo\_nvrmini\_upgrade\_rce -- No worky
    - Possibly the nvrmini reset exploit worked, because admin/admin worked on web console.
    - Once authenticated, used auth command injection and start an nc listener (side note: WHY DOES BUSYBOX HAVE NC COMPILED IN IT LULZ): [http://192.168.20.5/cgi-bin/cgi\_main?cmd=transfer\_license&amp;method=offline&amp;sn=%22%3bnc+-l+-p+45678+-e+/bin/sh+%26+%23](http://192.168.20.5/cgi-bin/cgi_main?cmd=transfer_license&amp;method=offline&amp;sn=%22%3Bnc+-l+-p+45678+-e+/bin/sh+%26+%23)
  - 20.2 – WesternDigital My Cloud EX4
    - Same same, vulnerable to is\_known\_pipename
  - 20.7 – AVTech Camera
    - POC script seemed to work, but was super slow. It was able to confirm code execution through running PS. Modified script and was executing at the time, but CTF ended before I could confirm that my modifications worked
    - [https://www.exploit-db.com/exploits/40500](https://www.exploit-db.com/exploits/40500)

Network Scans:

<details><summary>192.168.10.0</summary>

```
# Nmap 7.80 scan initiated Sat May 30 11:14:21 2020 as: nmap -sV -A -oN 10\_net\_scan 192.168.10.2-99
Nmap scan report for 192.168.10.4
Host is up (0.028s latency).
Not shown: 993 closed ports
PORT STATE SERVICE VERSION
80/tcp open http lighttpd 1.4.35
|\_http-generator: HTML Tidy, see www.w3.org
|\_http-server-header: lighttpd/1.4.35
|\_http-title: Site doesn&#39;t have a title (text/html).
139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open ssl/http lighttpd 1.4.35
|\_http-generator: HTML Tidy, see www.w3.org
|\_http-server-header: lighttpd/1.4.35
|\_http-title: Site doesn&#39;t have a title (text/html).
| ssl-cert: Subject: commonName=Seagate Technology LLC/organizationName=Seagate Technology LLC/stateOrProvinceName=California/countryName=US
| Not valid before: 2010-01-01T00:00:28
|\_Not valid after: 2020-01-02T00:00:28
|\_ssl-date: TLS randomness does not represent time
445/tcp open netbios-ssn Samba smbd 4.6.2 (workgroup: WORKGROUP)
548/tcp open afp
| afp-serverinfo:
| Server Flags:
| Flags hex: 0x8f5d
| Super Client: true
| UUIDs: true
| UTF8 Server Name: true
| Open Directory: true

| Reconnect: false

| Server Notifications: true

| TCP/IP: false

| Server Signature: true

| Server Messages: true

| Password Saving Prohibited: true

| Password Changing: false

| Copy File: true

| Server Name: PersonalCloud

| Machine Type: Netatalk3.1.8

| AFP Versions: AFP2.2, AFPX03, AFP3.1, AFP3.2, AFP3.3, AFP3.4

| UAMs: No User Authent, DHX2, DHCAST128, Cleartxt Passwrd

| Server Signature: 1db8ad465b301206413398274da0a73a

| Network Addresses:

| ::

|\_ UTF8 Server Name: PersonalCloud

| fingerprint-strings:

| afp:

| PersonalCloud

| Netatalk3.1.8

| AFP2.2

| AFPX03

| AFP3.1

| AFP3.2

| AFP3.3

| AFP3.4

| User Authent

| DHX2 DHCAST128

| Cleartxt Passwrd

|\_ PersonalCloud

2222/tcp open ssh OpenSSH 7.2 (protocol 2.0)

| ssh-hostkey:

| 2048 dd:5f:44:d3:69:8d:d1:ed:79:ee:12:b2:07:b8:11:bf (RSA)

| 256 d1:f5:b2:93:fe:4d:0c:33:34:fa:6d:0d:f5:fd:fc:8e (ECDSA)

|\_ 256 95:65:19:d1:6b:93:6e:68:3d:23:0c:6a:f0:67:f1:59 (ED25519)

9000/tcp open upnp TwonkyMedia UPnP (UPnP 1.0; pvConnect SDK 1.0; Twonky SDK 1.1)

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

SF-Port548-TCP:V=7.80%I=7%D=5/30%Time=5ED2785D%P=x86\_64-pc-linux-gnu%r(afp

SF:,1CD,&quot;\x01\x03\0\x01\0\0\0\0\0\0\x01\xbd\0\0\0\0\0\x20\0\.\0Y\0\x8a\x8f

SF:\]\rPersonalCloud\x01\x8a\x01\x9a\x01\xad\x01\xae\rNetatalk3\.1\.8\x06\

SF:x06AFP2\.2\x06AFPX03\x06AFP3\.1\x06AFP3\.2\x06AFP3\.3\x06AFP3\.4\x04\x0

SF:fNo\x20User\x20Authent\x04DHX2\tDHCAST128\x10Cleartxt\x20Passwrd\0\0\0\

SF:0\0\x80\x02\0\x01\x80\x03\0\x02\x80\x02\x80\x02\x80\x02\x80\x04\x80\x02

SF:@\x04\x87\xc2@\x04X4@\x04\x20\x08@\x02\x16\xd0\x80\x01\x01\x01\0\x02\x8

SF:0\x02\x80\x02\x9cr\x80\x04\&quot;\x88@\x04A\x04@\x04A\x04@\x04A\x04@\x04I\$@

SF:\x0eUT\xe0\x10\]t\x10\x10\&gt;\xf8\x10\x7f\xfc\x7f\xfe\x20\x04@\x04\x1f\xfc

SF:\x7f\xf8\0\x07\xc0\0\0\x04@\0\0\x03\x80\0\0\x04@\0\xaf\xf9\?\xf5\0\x02\

SF:x80\0\xaf\xfc\x7f\xf5\0\0\0\0\0\0\0\0\0\x80\x02\0\x01\x80\x03\0\x03\x80

SF:\x03\x80\x03\x80\x03\x80\x07\x80\x03\xc0\x07\x87\xc3\xc0\x07\xdf\xf7\xc

SF:0\x07\xff\xff\xc0\x03\xff\xff\x80\x01\xff\xff\0\x03\xff\xff\x80\x03\xff

SF:\xff\x80\x07\xff\xff\xc0\x07\xff\xff\xc0\x07\xff\xff\xc0\x07\xff\xff\xc

SF:0\x07\xff\xff\xc0\x0f\xff\xff\xe0\x1f\xff\xff\xf0\x1f\xff\xff\xf0\x7f\x

SF:ff\xff\xfe\?\xff\xff\xfc\x1f\xff\xff\xf8\0\x07\xc0\0\0\x07\xc0\0\0\x03\

SF:x80\0\0\x04@\0\xaf\xf9\?\xf5\0\x02\x80\0\xaf\xfc\x7f\xf5\0\0\0\0\x1d\xb

SF:8\xadF\[0\x12\x06A3\x98&#39;M\xa0\xa7:\x01\x12\x06\0\0\0\0\0\0\0\0\0\0\0\0\

SF:0\0\0\0\0\0\rPersonalCloud&quot;);

Service Info: Host: PERSONALCLOUD; OS: Linux; CPE: cpe:/o:linux:linux\_kernel:2

Host script results:

|\_clock-skew: mean: -3802d09h43m46s, deviation: 5h46m25s, median: -3802d13h03m47s

|\_nbstat: NetBIOS name: PERSONALCLOUD, NetBIOS user: \&lt;unknown\&gt;, NetBIOS MAC: \&lt;unknown\&gt; (unknown)

| smb-os-discovery:

| OS: Windows 6.1 (Samba 4.6.2)

| Computer name: personalcloud

| NetBIOS computer name: PERSONALCLOUD\x00

| Domain name: router-core-0.local

| FQDN: personalcloud.router-core-0.local

|\_ System time: 2009-12-31T16:13:33-10:00

| smb-security-mode:

| account\_used: guest

| authentication\_level: user

| challenge\_response: supported

|\_ message\_signing: supported

| smb2-security-mode:

| 2.02:

|\_ Message signing enabled but not required

| smb2-time:

| date: 2010-01-01T02:13:41

|\_ start\_date: N/A
```
```
Nmap scan report for 192.168.10.5

Host is up (0.031s latency).

Not shown: 988 closed ports

PORT STATE SERVICE VERSION

21/tcp open ftp

| fingerprint-strings:

| GenericLines:

| 220 TNAS-003489 FTP server (SmbFTPD Ver 2.7) ready.

| command not understood.

| command not understood.

| Help:

| 220 TNAS-003489 FTP server (SmbFTPD Ver 2.7) ready.

| 214- The following commands are recognized (\* =\&gt;&#39;s unimplemented).

| USER LPRT MODE MSOM\* RNTO SITE RMD SIZE PBSZ\*

| PASS EPRT RETR MSAM\* ABOR SYST XRMD MDTM PROT\*

| ACCT\* PASV STOR MRSQ\* DELE STAT PWD MLST

| SMNT\* LPSV APPE MRCP\* CWD HELP XPWD MLSD

| REIN\* EPSV MLFL\* ALLO XCWD NOOP CDUP FEAT

| QUIT TYPE MAIL\* REST LIST MKD XCUP OPTS

| PORT STRU MSND\* RNFR NLST XMKD STOU AUTH\*

| Direct comments to ftp-bugs@TNAS-003489.

| NULL, SMBProgNeg:

| 220 TNAS-003489 FTP server (SmbFTPD Ver 2.7) ready.

| SSLSessionReq:

| 220 TNAS-003489 FTP server (SmbFTPD Ver 2.7) ready.

|\_ command not understood.

23/tcp open telnet BusyBox telnetd

80/tcp open http Golang net/http server

| fingerprint-strings:

| FourOhFourRequest:

| HTTP/1.0 200 OK

| Date: Thu, 06 Sep 2012 15:12:03 GMT

| Content-Length: 72

| Content-Type: text/html; charset=utf-8

| \&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location.href=&#39;http://:8181&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;

| GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5:

| HTTP/1.1 400 Bad Request

| Content-Type: text/plain

| Connection: close

| Request

| GetRequest, HTTPOptions:

| HTTP/1.0 200 OK

| Date: Thu, 06 Sep 2012 15:11:58 GMT

| Content-Length: 72

| Content-Type: text/html; charset=utf-8

| \&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location.href=&#39;http://:8181&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;

| OfficeScan:

| HTTP/1.1 400 Bad Request

| Content-Type: text/plain

| Connection: close

|\_ Request: missing required Host header

|\_http-title: Site doesn&#39;t have a title (text/html; charset=utf-8).

111/tcp open rpcbind 2-4 (RPC #100000)

| rpcinfo:

| program version port/proto service

| 100000 2,3,4 111/tcp rpcbind

| 100000 2,3,4 111/udp rpcbind

| 100000 3,4 111/tcp6 rpcbind

| 100000 3,4 111/udp6 rpcbind

| 100003 2,3,4 2049/tcp nfs

| 100003 2,3,4 2049/udp nfs

| 100005 1,2,3 37063/udp mountd

| 100005 1,2,3 52642/tcp mountd

| 100021 1,3,4 37532/udp nlockmgr

| 100021 1,3,4 39860/tcp6 nlockmgr

| 100021 1,3,4 45549/udp6 nlockmgr

| 100021 1,3,4 52730/tcp nlockmgr

| 100024 1 36698/tcp status

| 100024 1 60860/udp status

| 100227 2,3 2049/tcp nfs\_acl

|\_ 100227 2,3 2049/udp nfs\_acl

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/http Golang net/http server

| fingerprint-strings:

| FourOhFourRequest, HTTPOptions:

| HTTP/1.0 200 OK

| Date: Thu, 06 Sep 2012 15:12:05 GMT

| Content-Length: 73

| Content-Type: text/html; charset=utf-8

| \&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location.href=&#39;https://:5443&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;

| GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5:

| HTTP/1.1 400 Bad Request

| Content-Type: text/plain

| Connection: close

| Request

| GetRequest:

| HTTP/1.0 200 OK

| Date: Thu, 06 Sep 2012 15:12:04 GMT

| Content-Length: 73

| Content-Type: text/html; charset=utf-8

| \&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location.href=&#39;https://:5443&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;

| OfficeScan:

| HTTP/1.1 400 Bad Request

| Content-Type: text/plain

| Connection: close

|\_ Request: missing required Host header

|\_http-title: Site doesn&#39;t have a title (text/html; charset=utf-8).

| ssl-cert: Subject: commonName=\*.tnas.link/countryName=US

| Subject Alternative Name: DNS:\*.tnas.link, DNS:tnas.link

| Not valid before: 2017-10-20T08:36:50

|\_Not valid after: 2018-10-20T08:36:50

|\_ssl-date: TLS randomness does not represent time

| tls-alpn:

| h2

|\_ http/1.1

| tls-nextprotoneg:

| h2

| h2-14

|\_ http/1.1

445/tcp open netbios-ssn Samba smbd 4.3.0 (workgroup: WORKGROUP)

548/tcp open afp Netatalk 3.1.11 (name: TNAS-003489; protocol 3.4)

| afp-serverinfo:

| Server Flags:

| Flags hex: 0x8f7d

| Super Client: true

| UUIDs: true

| UTF8 Server Name: true

| Open Directory: true

| Reconnect: false

| Server Notifications: true

| TCP/IP: true

| Server Signature: true

| Server Messages: true

| Password Saving Prohibited: true

| Password Changing: false

| Copy File: true

| Server Name: TNAS-003489

| Machine Type: Netatalk3.1.11

| AFP Versions: AFP2.2, AFPX03, AFP3.1, AFP3.2, AFP3.3, AFP3.4

| UAMs: No User Authent, DHX2, DHCAST128

| Server Signature: d84d12209f31ec25bdc83c76d46e9d58

| Network Addresses:

| 169.254.254.191

|\_ UTF8 Server Name: TNAS-003489

2049/tcp open nfs\_acl 2-3 (RPC #100227)

3260/tcp open iscsi?

|\_iscsi-info:

8181/tcp open http nginx 1.9.4

|\_http-server-header: nginx/1.9.4

|\_http-title: TOS Loading

49152/tcp open upnp Portable SDK for UPnP devices 1.6.19 (Linux 4.0.0; UPnP 1.0)

3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port21-TCP:V=7.80%I=7%D=5/30%Time=5ED27857%P=x86\_64-pc-linux-gnu%r(NULL

SF:,35,&quot;220\x20TNAS-003489\x20FTP\x20server\x20\(SmbFTPD\x20Ver\x202\.7\)\

SF:x20ready\.\r\n&quot;)%r(GenericLines,73,&quot;220\x20TNAS-003489\x20FTP\x20server

SF:\x20\(SmbFTPD\x20Ver\x202\.7\)\x20ready\.\r\n500\x20:\x20command\x20not

SF:\x20understood\.\r\n500\x20:\x20command\x20not\x20understood\.\r\n&quot;)%r(

SF:Help,285,&quot;220\x20TNAS-003489\x20FTP\x20server\x20\(SmbFTPD\x20Ver\x202\

SF:.7\)\x20ready\.\r\n214-\x20The\x20following\x20commands\x20are\x20recog

SF:nized\x20\(\*\x20=\&gt;&#39;s\x20unimplemented\)\.\r\n\x20\x20\x20USER\x20\x20\

SF:x20\x20LPRT\x20\x20\x20\x20MODE\x20\x20\x20\x20MSOM\*\x20\x20\x20RNTO\x

SF:20\x20\x20\x20SITE\x20\x20\x20\x20RMD\x20\x20\x20\x20\x20SIZE\x20\x20\x

SF:20\x20PBSZ\*\r\n\x20\x20\x20PASS\x20\x20\x20\x20EPRT\x20\x20\x20\x20RET

SF:R\x20\x20\x20\x20MSAM\*\x20\x20\x20ABOR\x20\x20\x20\x20SYST\x20\x20\x20

SF:\x20XRMD\x20\x20\x20\x20MDTM\x20\x20\x20\x20PROT\*\r\n\x20\x20\x20ACCT\

SF:\*\x20\x20\x20PASV\x20\x20\x20\x20STOR\x20\x20\x20\x20MRSQ\*\x20\x20\x20

SF:DELE\x20\x20\x20\x20STAT\x20\x20\x20\x20PWD\x20\x20\x20\x20\x20MLST\x20

SF:\r\n\x20\x20\x20SMNT\*\x20\x20\x20LPSV\x20\x20\x20\x20APPE\x20\x20\x20\

SF:x20MRCP\*\x20\x20\x20CWD\x20\x20\x20\x20\x20HELP\x20\x20\x20\x20XPWD\x2

SF:0\x20\x20\x20MLSD\x20\r\n\x20\x20\x20REIN\*\x20\x20\x20EPSV\x20\x20\x20

SF:\x20MLFL\*\x20\x20\x20ALLO\x20\x20\x20\x20XCWD\x20\x20\x20\x20NOOP\x20\

SF:x20\x20\x20CDUP\x20\x20\x20\x20FEAT\x20\r\n\x20\x20\x20QUIT\x20\x20\x20

SF:\x20TYPE\x20\x20\x20\x20MAIL\*\x20\x20\x20REST\x20\x20\x20\x20LIST\x20\

SF:x20\x20\x20MKD\x20\x20\x20\x20\x20XCUP\x20\x20\x20\x20OPTS\x20\r\n\x20\

SF:x20\x20PORT\x20\x20\x20\x20STRU\x20\x20\x20\x20MSND\*\x20\x20\x20RNFR\x

SF:20\x20\x20\x20NLST\x20\x20\x20\x20XMKD\x20\x20\x20\x20STOU\x20\x20\x20\

SF:x20AUTH\*\r\n214\x20Direct\x20comments\x20to\x20ftp-bugs@TNAS-003489\.\

SF:r\n&quot;)%r(SSLSessionReq,56,&quot;220\x20TNAS-003489\x20FTP\x20server\x20\(SmbF

SF:TPD\x20Ver\x202\.7\)\x20ready\.\r\n500\x20\x16\x03:\x20command\x20not\x

SF:20understood\.\r\n&quot;)%r(SMBProgNeg,35,&quot;220\x20TNAS-003489\x20FTP\x20serv

SF:er\x20\(SmbFTPD\x20Ver\x202\.7\)\x20ready\.\r\n&quot;);

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port80-TCP:V=7.80%I=7%D=5/30%Time=5ED27857%P=x86\_64-pc-linux-gnu%r(GetR

SF:equest,BC,&quot;HTTP/1\.0\x20200\x20OK\r\nDate:\x20Thu,\x2006\x20Sep\x202012

SF:\x2015:11:58\x20GMT\r\nContent-Length:\x2072\r\nContent-Type:\x20text/h

SF:tml;\x20charset=utf-8\r\n\r\n\&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location\.href=&#39;http:/

SF:/:8181&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;&quot;)%r(HTTPOptions,BC,&quot;HTTP/1\.0\x20200\x2

SF:0OK\r\nDate:\x20Thu,\x2006\x20Sep\x202012\x2015:11:58\x20GMT\r\nContent

SF:-Length:\x2072\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\n\r\n\&lt;

SF:html\&gt;\&lt;body\&gt;\&lt;script\&gt;location\.href=&#39;http://:8181&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html

SF:\&gt;&quot;)%r(RTSPRequest,58,&quot;HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ

SF:e:\x20text/plain\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)

SF:%r(FourOhFourRequest,BC,&quot;HTTP/1\.0\x20200\x20OK\r\nDate:\x20Thu,\x2006\

SF:x20Sep\x202012\x2015:12:03\x20GMT\r\nContent-Length:\x2072\r\nContent-T

SF:ype:\x20text/html;\x20charset=utf-8\r\n\r\n\&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location

SF:\.href=&#39;http://:8181&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;&quot;)%r(GenericLines,58,&quot;HTTP

SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnec

SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(Help,58,&quot;HTTP/1\.1\x204

SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20c

SF:lose\r\n\r\n400\x20Bad\x20Request&quot;)%r(SSLSessionReq,58,&quot;HTTP/1\.1\x2040

SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20cl

SF:ose\r\n\r\n400\x20Bad\x20Request&quot;)%r(LPDString,58,&quot;HTTP/1\.1\x20400\x20

SF:Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20close\r

SF:\n\r\n400\x20Bad\x20Request&quot;)%r(SIPOptions,58,&quot;HTTP/1\.1\x20400\x20Bad\

SF:x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20close\r\n\r

SF:\n400\x20Bad\x20Request&quot;)%r(Socks5,58,&quot;HTTP/1\.1\x20400\x20Bad\x20Reque

SF:st\r\nContent-Type:\x20text/plain\r\nConnection:\x20close\r\n\r\n400\x2

SF:0Bad\x20Request&quot;)%r(OfficeScan,76,&quot;HTTP/1\.1\x20400\x20Bad\x20Request\r

SF:\nContent-Type:\x20text/plain\r\nConnection:\x20close\r\n\r\n400\x20Bad

SF:\x20Request:\x20missing\x20required\x20Host\x20header&quot;);

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port443-TCP:V=7.80%T=SSL%I=7%D=5/30%Time=5ED2785E%P=x86\_64-pc-linux-gnu

SF:%r(GetRequest,BD,&quot;HTTP/1\.0\x20200\x20OK\r\nDate:\x20Thu,\x2006\x20Sep\

SF:x202012\x2015:12:04\x20GMT\r\nContent-Length:\x2073\r\nContent-Type:\x2

SF:0text/html;\x20charset=utf-8\r\n\r\n\&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location\.href=

SF:&#39;https://:5443&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;&quot;)%r(HTTPOptions,BD,&quot;HTTP/1\.0\x

SF:20200\x20OK\r\nDate:\x20Thu,\x2006\x20Sep\x202012\x2015:12:05\x20GMT\r\

SF:nContent-Length:\x2073\r\nContent-Type:\x20text/html;\x20charset=utf-8\

SF:r\n\r\n\&lt;html\&gt;\&lt;body\&gt;\&lt;script\&gt;location\.href=&#39;https://:5443&#39;;\&lt;/script\&gt;\&lt;/bo

SF:dy\&gt;\&lt;/html\&gt;&quot;)%r(FourOhFourRequest,BD,&quot;HTTP/1\.0\x20200\x20OK\r\nDate:\x2

SF:0Thu,\x2006\x20Sep\x202012\x2015:12:05\x20GMT\r\nContent-Length:\x2073\

SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\n\r\n\&lt;html\&gt;\&lt;body\&gt;\&lt;scr

SF:ipt\&gt;location\.href=&#39;https://:5443&#39;;\&lt;/script\&gt;\&lt;/body\&gt;\&lt;/html\&gt;&quot;)%r(GenericL

SF:ines,58,&quot;HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl

SF:ain\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(RTSPReques

SF:t,58,&quot;HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain

SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(Help,58,&quot;HTTP

SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnec

SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(SSLSessionReq,58,&quot;HTTP/

SF:1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnect

SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(LPDString,58,&quot;HTTP/1\.1\

SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\

SF:x20close\r\n\r\n400\x20Bad\x20Request&quot;)%r(SIPOptions,58,&quot;HTTP/1\.1\x204

SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20c

SF:lose\r\n\r\n400\x20Bad\x20Request&quot;)%r(Socks5,58,&quot;HTTP/1\.1\x20400\x20Ba

SF:d\x20Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20close\r\n

SF:\r\n400\x20Bad\x20Request&quot;)%r(OfficeScan,76,&quot;HTTP/1\.1\x20400\x20Bad\x2

SF:0Request\r\nContent-Type:\x20text/plain\r\nConnection:\x20close\r\n\r\n

SF:400\x20Bad\x20Request:\x20missing\x20required\x20Host\x20header&quot;);

Service Info: Host: TNAS-003489; OSs: Unix, Linux; CPE: cpe:/o:linux:linux\_kernel:4.0.0

Host script results:

|\_clock-skew: mean: -2823d02h42m29s, deviation: 4h37m01s, median: -2823d00h02m33s

|\_nbstat: NetBIOS name: TNAS-003489, NetBIOS user: \&lt;unknown\&gt;, NetBIOS MAC: \&lt;unknown\&gt; (unknown)

| smb-os-discovery:

| OS: Windows 6.1 (Samba 4.3.0)

| Computer name: tnas-003489

| NetBIOS computer name: TNAS-003489\x00

| Domain name:

| FQDN: tnas-003489

|\_ System time: 2012-09-06T23:14:56+08:00

| smb-security-mode:

| account\_used: \&lt;blank\&gt;

| authentication\_level: user

| challenge\_response: supported

|\_ message\_signing: disabled (dangerous, but default)

| smb2-security-mode:

| 2.02:

|\_ Message signing enabled but not required

| smb2-time:

| date: 2012-09-06T15:14:54

|\_ start\_date: N/A
```

</details>





```
Nmap scan report for 192.168.10.6

Host is up (0.031s latency).

Not shown: 990 closed ports

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 5.9 (protocol 2.0)

| ssh-hostkey:

| 1024 ef:53:8c:07:05:8d:75:30:e8:65:ad:7f:e6:fe:30:36 (DSA)

| 2048 3f:14:ca:02:19:13:c6:37:ea:8a:fe:74:e0:b4:6f:00 (RSA)

|\_ 256 78:d9:7b:04:17:dc:9f:a1:f4:13:eb:5d:b1:51:96:a6 (ECDSA)

80/tcp open http

| fingerprint-strings:

| DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:

|\_ HTTP/1.0 503 Service unavailable

|\_http-title: Did not follow redirect to http://192.168.10.6:8000/

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/https

| fingerprint-strings:

| DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, ms-sql-s, oracle-tns, tor-versions:

|\_ HTTP/1.0 503 Service unavailable

|\_http-title: Did not follow redirect to https://192.168.10.6:8001/

| ssl-cert: Subject: commonName=Support/organizationName=Asustor/stateOrProvinceName=Taiwan/countryName=TW

| Not valid before: 2012-11-30T06:44:49

|\_Not valid after: 2022-11-28T06:44:49

|\_ssl-date: TLS randomness does not represent time

445/tcp open netbios-ssn Samba smbd 4.4.3 (workgroup: WORKGROUP)

631/tcp open ipp CUPS 1.7

| http-methods:

|\_ Potentially risky methods: PUT

|\_http-server-header: CUPS/1.7 IPP/2.1

|\_http-title: Not Found - CUPS v1.7.2

873/tcp open rsync?

3260/tcp open iscsi?

|\_iscsi-info:

8000/tcp open http lighttpd 1.4.29-devel-162

| http-robots.txt: 1 disallowed entry

|\_/

|\_http-server-header: lighttpd/1.4.29-devel-162

|\_http-title: Site doesn&#39;t have a title (text/html; charset=utf-8).

8001/tcp open ssl/http lighttpd 1.4.29-devel-162

| http-robots.txt: 1 disallowed entry

|\_/

|\_http-server-header: lighttpd/1.4.29-devel-162

|\_http-title: Site doesn&#39;t have a title (text/html; charset=utf-8).

| ssl-cert: Subject: commonName=Support/organizationName=Asustor/stateOrProvinceName=Taiwan/countryName=TW

| Not valid before: 2012-11-30T06:44:49

|\_Not valid after: 2022-11-28T06:44:49

|\_ssl-date: TLS randomness does not represent time

2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port80-TCP:V=7.80%I=7%D=5/30%Time=5ED27858%P=x86\_64-pc-linux-gnu%r(GetR

SF:equest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(HTTPO

SF:ptions,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(RTSPR

SF:equest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(X11Pr

SF:obe,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(FourOhFo

SF:urRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(Ge

SF:nericLines,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(R

SF:PCCheck,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(DNSV

SF:ersionBindReqTCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n

SF:&quot;)%r(DNSStatusRequestTCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable

SF:\r\n\r\n&quot;)%r(Help,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\

SF:n&quot;)%r(SSLSessionReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\

SF:r\n&quot;)%r(TerminalServerCookie,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavail

SF:able\r\n\r\n&quot;)%r(TLSSessionReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20unava

SF:ilable\r\n\r\n&quot;)%r(Kerberos,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavaila

SF:ble\r\n\r\n&quot;)%r(SMBProgNeg,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailab

SF:le\r\n\r\n&quot;)%r(LPDString,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable

SF:\r\n\r\n&quot;)%r(LDAPSearchReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailab

SF:le\r\n\r\n&quot;)%r(LDAPBindReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailab

SF:le\r\n\r\n&quot;)%r(SIPOptions,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailabl

SF:e\r\n\r\n&quot;)%r(LANDesk-RC,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable

SF:\r\n\r\n&quot;)%r(TerminalServer,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavaila

SF:ble\r\n\r\n&quot;)%r(NCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\

SF:r\n&quot;)%r(NotesRPC,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n

SF:&quot;)%r(JavaRMI,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r

SF:(WMSRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(

SF:oracle-tns,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(m

SF:s-sql-s,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(afp,

SF:24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%r(giop,24,&quot;HTT

SF:P/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;);

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port443-TCP:V=7.80%T=SSL%I=7%D=5/30%Time=5ED2785E%P=x86\_64-pc-linux-gnu

SF:%r(GetRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%

SF:r(HTTPOptions,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;)%

SF:r(FourOhFourRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\

SF:r\n&quot;)%r(tor-versions,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n

SF:\r\n&quot;)%r(GenericLines,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\

SF:n\r\n&quot;)%r(RTSPRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\

SF:n\r\n&quot;)%r(RPCCheck,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r

SF:\n&quot;)%r(DNSVersionBindReqTCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavaila

SF:ble\r\n\r\n&quot;)%r(DNSStatusRequestTCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20

SF:unavailable\r\n\r\n&quot;)%r(Help,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavail

SF:able\r\n\r\n&quot;)%r(SSLSessionReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20unava

SF:ilable\r\n\r\n&quot;)%r(TerminalServerCookie,24,&quot;HTTP/1\.0\x20503\x20Service

SF:\x20unavailable\r\n\r\n&quot;)%r(TLSSessionReq,24,&quot;HTTP/1\.0\x20503\x20Servi

SF:ce\x20unavailable\r\n\r\n&quot;)%r(Kerberos,24,&quot;HTTP/1\.0\x20503\x20Service\

SF:x20unavailable\r\n\r\n&quot;)%r(SMBProgNeg,24,&quot;HTTP/1\.0\x20503\x20Service\x

SF:20unavailable\r\n\r\n&quot;)%r(X11Probe,24,&quot;HTTP/1\.0\x20503\x20Service\x20u

SF:navailable\r\n\r\n&quot;)%r(LPDString,24,&quot;HTTP/1\.0\x20503\x20Service\x20una

SF:vailable\r\n\r\n&quot;)%r(LDAPSearchReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20u

SF:navailable\r\n\r\n&quot;)%r(LDAPBindReq,24,&quot;HTTP/1\.0\x20503\x20Service\x20u

SF:navailable\r\n\r\n&quot;)%r(SIPOptions,24,&quot;HTTP/1\.0\x20503\x20Service\x20un

SF:available\r\n\r\n&quot;)%r(LANDesk-RC,24,&quot;HTTP/1\.0\x20503\x20Service\x20una

SF:vailable\r\n\r\n&quot;)%r(TerminalServer,24,&quot;HTTP/1\.0\x20503\x20Service\x20

SF:unavailable\r\n\r\n&quot;)%r(NCP,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavaila

SF:ble\r\n\r\n&quot;)%r(NotesRPC,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable

SF:\r\n\r\n&quot;)%r(JavaRMI,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n

SF:\r\n&quot;)%r(WMSRequest,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\

SF:r\n&quot;)%r(oracle-tns,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r

SF:\n&quot;)%r(ms-sql-s,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;

SF:)%r(afp,24,&quot;HTTP/1\.0\x20503\x20Service\x20unavailable\r\n\r\n&quot;);

Service Info: Host: AS-602T-EDE6

Host script results:

|\_clock-skew: mean: -4m57s, deviation: 13s, median: -5m07s

|\_nbstat: NetBIOS name: AS-602T-EDE6, NetBIOS user: \&lt;unknown\&gt;, NetBIOS MAC: \&lt;unknown\&gt; (unknown)

| smb-os-discovery:

| OS: Windows 6.1 (Samba 4.4.3)

| Computer name: as-602t-ede6

| NetBIOS computer name: AS-602T-EDE6\x00

| Domain name: \x00

| FQDN: as-602t-ede6

|\_ System time: 2020-05-30T15:12:30+00:00

| smb-security-mode:

| account\_used: guest

| authentication\_level: user

| challenge\_response: supported

|\_ message\_signing: disabled (dangerous, but default)

|\_smb2-time: Protocol negotiation failed (SMB2)
```

```
Nmap scan report for 192.168.10.7

Host is up (0.031s latency).

Not shown: 997 closed ports

PORT STATE SERVICE VERSION

80/tcp open http

| fingerprint-strings:

| DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 25

| Connection: close

| Found

| Resource:

| FourOhFourRequest:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 61

| Connection: close

| Found

| Resource: /nice%20ports%2C/Tri%6Eity.txt%2ebak

| HTTPOptions, RTSPRequest:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 26

| Connection: close

| Found

|\_ Resource: /

|\_http-title: Site doesn&#39;t have a title (text/html).

443/tcp open ssl/https

| fingerprint-strings:

| DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, RPCCheck, SSLSessionReq, TLSSessionReq, TerminalServerCookie, tor-versions:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 25

| Connection: close

| Found

| Resource:

| FourOhFourRequest:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 61

| Connection: close

| Found

| Resource: /nice%20ports%2C/Tri%6Eity.txt%2ebak

| HTTPOptions, RTSPRequest:

| HTTP/1.1 404 Not Found

| Content-Type: text/plain

| Content-Length: 26

| Connection: close

| Found

|\_ Resource: /

| ssl-cert: Subject: commonName=www.geovision.com.tw/organizationName=GeoVision/stateOrProvinceName=Taiwan/countryName=TW

| Not valid before: 2016-01-22T07:00:40

|\_Not valid after: 2026-01-19T07:00:40

|\_ssl-date: TLS randomness does not represent time

10000/tcp open vss GeoVision IP camera Video Streaming Service

2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port80-TCP:V=7.80%I=7%D=5/30%Time=5ED27863%P=x86\_64-pc-linux-gnu%r(HTTP

SF:Options,75,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/p

SF:lain\r\nContent-Length:\x2026\r\nConnection:\x20close\r\n\r\n404\x20Not

SF:\x20Found\nResource:\x20/\n&quot;)%r(RTSPRequest,75,&quot;HTTP/1\.1\x20404\x20Not

SF:\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2026\r\nCo

SF:nnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20/\n&quot;)%r(X11

SF:Probe,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/pla

SF:in\r\nContent-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x

SF:20Found\nResource:\x20\n&quot;)%r(FourOhFourRequest,98,&quot;HTTP/1\.1\x20404\x20

SF:Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2061\r\

SF:nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20/nice%20

SF:ports%2C/Tri%6Eity\.txt%2ebak\n&quot;)%r(RPCCheck,74,&quot;HTTP/1\.1\x20404\x20No

SF:t\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nC

SF:onnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(DNS

SF:VersionBindReqTCP,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:

SF:\x20text/plain\r\nContent-Length:\x2025\r\nConnection:\x20close\r\n\r\n

SF:404\x20Not\x20Found\nResource:\x20\n&quot;)%r(DNSStatusRequestTCP,74,&quot;HTTP/1

SF:\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Le

SF:ngth:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResourc

SF:e:\x20\n&quot;)%r(SSLSessionReq,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nCont

SF:ent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nConnection:\x20clos

SF:e\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(TerminalServerCookie,

SF:74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\n

SF:Content-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Foun

SF:d\nResource:\x20\n&quot;)%r(TLSSessionReq,74,&quot;HTTP/1\.1\x20404\x20Not\x20Fou

SF:nd\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nConnectio

SF:n:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(Kerberos,74

SF:,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\nCo

SF:ntent-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\

SF:nResource:\x20\n&quot;)%r(SMBProgNeg,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\

SF:nContent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nConnection:\x2

SF:0close\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;);

==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============

SF-Port443-TCP:V=7.80%T=SSL%I=7%D=5/30%Time=5ED2786C%P=x86\_64-pc-linux-gnu

SF:%r(HTTPOptions,75,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x2

SF:0text/plain\r\nContent-Length:\x2026\r\nConnection:\x20close\r\n\r\n404

SF:\x20Not\x20Found\nResource:\x20/\n&quot;)%r(FourOhFourRequest,98,&quot;HTTP/1\.1\

SF:x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length

SF::\x2061\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x

SF:20/nice%20ports%2C/Tri%6Eity\.txt%2ebak\n&quot;)%r(tor-versions,74,&quot;HTTP/1\.

SF:1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Leng

SF:th:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:

SF:\x20\n&quot;)%r(RTSPRequest,75,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-

SF:Type:\x20text/plain\r\nContent-Length:\x2026\r\nConnection:\x20close\r\

SF:n\r\n404\x20Not\x20Found\nResource:\x20/\n&quot;)%r(RPCCheck,74,&quot;HTTP/1\.1\x

SF:20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length:

SF:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x2

SF:0\n&quot;)%r(DNSVersionBindReqTCP,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nCo

SF:ntent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nConnection:\x20cl

SF:ose\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(DNSStatusRequestTCP

SF:,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/plain\r\

SF:nContent-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20Not\x20Fou

SF:nd\nResource:\x20\n&quot;)%r(SSLSessionReq,74,&quot;HTTP/1\.1\x20404\x20Not\x20Fo

SF:und\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2025\r\nConnecti

SF:on:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(TerminalSe

SF:rverCookie,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20tex

SF:t/plain\r\nContent-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20

SF:Not\x20Found\nResource:\x20\n&quot;)%r(TLSSessionReq,74,&quot;HTTP/1\.1\x20404\x2

SF:0Not\x20Found\r\nContent-Type:\x20text/plain\r\nContent-Length:\x2025\r

SF:\nConnection:\x20close\r\n\r\n404\x20Not\x20Found\nResource:\x20\n&quot;)%r(

SF:Kerberos,74,&quot;HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Type:\x20text/

SF:plain\r\nContent-Length:\x2025\r\nConnection:\x20close\r\n\r\n404\x20No

SF:t\x20Found\nResource:\x20\n&quot;);

Service Info: Device: webcam

```

```
Nmap scan report for 192.168.10.8

Host is up (0.028s latency).

Not shown: 991 closed ports

PORT STATE SERVICE VERSION

21/tcp open ftp Pure-FTPd

| ssl-cert: Subject: commonName=NSA325-v2/organizationName=ZyXEL

| Not valid before: 2018-10-31T14:17:55

|\_Not valid after: 2021-10-30T14:17:55

|\_ssl-date: TLS randomness does not represent time

22/tcp open ssh OpenSSH 6.7 (protocol 2.0)

| ssh-hostkey:

| 1024 7e:67:04:3f:34:0b:9b:4c:8f:4b:59:ab:a9:91:3d:55 (DSA)

|\_ 2048 e5:bb:a6:03:31:e7:5e:24:3b:9c:67:c6:62:76:f8:79 (RSA)

80/tcp open http Apache httpd

|\_http-server-header: Apache

| http-title: Index\_Page

|\_Requested resource was /r51009,/adv,/index.html

|\_http-trane-info: Problem with XML parsing of /evox/about

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/http Apache httpd

|\_http-server-header: Apache

| http-title: Index\_Page

|\_Requested resource was /r51009,/adv,/index.html

|\_http-trane-info: Problem with XML parsing of /evox/about

| ssl-cert: Subject: commonName=NSA325-v2/organizationName=ZyXEL

| Not valid before: 2018-10-31T14:17:55

|\_Not valid after: 2021-10-30T14:17:55

445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

631/tcp open ipp CUPS 1.1

| http-methods:

|\_ Potentially risky methods: PUT

|\_http-server-header: CUPS/1.1

|\_http-title: 403 Forbidden

8082/tcp open http Apache httpd

|\_http-server-header: Apache

| http-title: Index\_Page

|\_Requested resource was /r51009,/adv,/index.html

|\_http-trane-info: Problem with XML parsing of /evox/about

9001/tcp open upnp TwonkyMedia UPnP (UPnP 1.0; pvConnect SDK 1.0; Twonky SDK 1.1)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux\_kernel:2

Host script results:

|\_clock-skew: -17m01s

|\_nbstat: NetBIOS name: NSA325-V2, NetBIOS user: \&lt;unknown\&gt;, NetBIOS MAC: \&lt;unknown\&gt; (unknown)

| smb-security-mode:

| account\_used: guest

| authentication\_level: user

| challenge\_response: supported

|\_ message\_signing: disabled (dangerous, but default)

|\_smb2-time: Protocol negotiation failed (SMB2)

Nmap scan report for 192.168.10.18

Host is up (0.030s latency).

Not shown: 989 closed ports

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 5.7 (protocol 2.0)

| ssh-hostkey:

| 1024 85:e5:2f:93:06:24:8d:48:5f:ee:17:a3:bc:ed:ca:f7 (DSA)

|\_ 2048 f3:5b:2d:c6:3e:17:ab:ce:52:66:52:2f:49:cc:72:aa (RSA)

80/tcp open http lighttpd 1.4.35

|\_http-server-header: lighttpd/1.4.35

|\_http-title: BUFFALO

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/https?

|\_ssl-date: TLS randomness does not represent time

445/tcp open netbios-ssn Samba smbd 3.6.25-75.osstech (workgroup: WORKGROUP)

515/tcp open printer?

548/tcp open afp Netatalk 2.2.2 (name: TS5600D0D8; protocol 3.3)

| afp-serverinfo:

| Server Flags:

| Flags hex: 0x8f79

| Super Client: true

| UUIDs: true

| UTF8 Server Name: true

| Open Directory: true

| Reconnect: false

| Server Notifications: true

| TCP/IP: true

| Server Signature: true

| Server Messages: true

| Password Saving Prohibited: false

| Password Changing: false

| Copy File: true

| Server Name: TS5600D0D8

| Machine Type: Netatalk2.2.2

| AFP Versions: AFP2.2, AFPX03, AFP3.1, AFP3.2, AFP3.3

| UAMs: DHX2, DHCAST128, Cleartxt Passwrd, No User Authent

| Server Signature: 4aeafbba319418c88af6fb17c299ec6a

| Network Addresses:

| 192.168.10.18

|\_ UTF8 Server Name: TS5600D0D8

873/tcp open rsync (protocol version 31)

8873/tcp open ssl/dxspider?

9050/tcp open http BaseHTTPServer 0.3 (Python 2.7.9)

22939/tcp open ssl/unknown

Service Info: OS: Unix

Host script results:

|\_clock-skew: mean: -51062d03h25m27s, deviation: 88442d09h45m26s, median: 26s

|\_nbstat: NetBIOS name: TS5600D0D8, NetBIOS user: \&lt;unknown\&gt;, NetBIOS MAC: \&lt;unknown\&gt; (unknown)

| smb-os-discovery:

| OS: Unix (Samba 3.6.25-75.osstech)

| Computer name: TS5600D0D8

| NetBIOS computer name:

| Domain name:

| FQDN: TS5600D0D8

|\_ System time: 2020-05-30T10:17:58-05:00

| smb-security-mode:

| account\_used: guest

| authentication\_level: user

| challenge\_response: supported

|\_ message\_signing: disabled (dangerous, but default)

| smb2-security-mode:

| 2.02:

|\_ Message signing enabled but not required

| smb2-time:

| date: 1601-01-01T00:00:00

|\_ start\_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat May 30 11:22:07 2020 -- 98 IP addresses (6 hosts up) scanned in 465.49 seconds

192.168.20.0:

# Nmap 7.80 scan initiated Sat May 30 14:30:35 2020 as: nmap -sV -oN 20\_net\_scan 192.168.20.2,3,5,7,9
```

```
Nmap scan report for 192.168.20.2

Host is up (0.031s latency).

Not shown: 994 closed ports

PORT STATE SERVICE VERSION

80/tcp open http lighttpd 1.4.33

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/https?

445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

548/tcp open afp Netatalk 3.0.5 (name: WDMyCloudEX4; protocol 3.3)

49152/tcp open upnp Portable SDK for UPnP devices 1.6.6 (Linux 3.2.40; UPnP 1.0)

Service Info: Host: WDMYCLOUDEX4; OSs: Unix, Linux; CPE: cpe:/o:linux:linux\_kernel:3.2.40
```

```
Nmap scan report for 192.168.20.3

Host is up (0.029s latency).

Not shown: 987 closed ports

PORT STATE SERVICE VERSION

21/tcp open ftp ProFTPD 1.2.10

22/tcp open ssh OpenSSH 7.0 (protocol 2.0)

80/tcp open http Apache httpd

139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

443/tcp open ssl/http QNAP NAS http config

445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

631/tcp open ipp CUPS 1.6

873/tcp open rsync?

6881/tcp open tcpwrapped

8080/tcp open http QNAP NAS http config

8081/tcp open http Apache httpd

8200/tcp open upnp QNAP DLNA 1.0 (DLNADOC 1.50; UPnP 1.0)

49152/tcp open upnp Portable SDK for UPnP devices 1.6.19 (Linux 3.19.8; UPnP 1.0)

Service Info: Hosts: NAS10CA01, 192.168.20.3; OSs: Linux 3.4.6, Linux; Device: storage-misc; CPE: cpe:/o:linux:linux\_kernel:3.4.6, cpe:/o:linux:linux\_kernel:3.19.8
```

```
Nmap scan report for 192.168.20.5

Host is up (0.030s latency).

Not shown: 996 closed ports

PORT STATE SERVICE VERSION

21/tcp open ftp ProFTPD 1.3.3c

22/tcp open ssh Dropbear sshd 2015.67 (protocol 2.0)

80/tcp open http lighttpd 1.4.39

443/tcp open ssl/https?

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux\_kernel
```

```
Nmap scan report for 192.168.20.7

Host is up (0.030s latency).

Not shown: 998 closed ports

PORT STATE SERVICE VERSION

80/tcp open http Avtech AVN801 network camera 1.0 (UPnP 1.0)

554/tcp open http Avtech AVN801 network camera 1.0 (UPnP 1.0)

Service Info: OS: Linux; Device: webcam; CPE: cpe:/h:avtech:avn801, cpe:/o:linux:linux\_kernel
```

```
Nmap scan report for 192.168.20.9

Host is up (0.031s latency).

Not shown: 996 closed ports

PORT STATE SERVICE VERSION

22/tcp open ssh OpenSSH 5.9 (protocol 2.0)

80/tcp open http Cherokee httpd 1.2.101b130912\_312f8b6

8888/tcp open sun-answerbook?

9998/tcp open distinct32?

Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

# Nmap done at Sat May 30 14:35:56 2020 -- 5 IP addresses (5 hosts up) scanned in 320.88 seconds

```
