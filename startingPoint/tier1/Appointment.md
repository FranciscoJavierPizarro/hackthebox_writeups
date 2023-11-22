#veryeasy 
#web 
#sqlinjection 


**Reconnaissance**
The recon phase involves gathering information about the target to identify potential vulnerabilities. In this case, we used the Nmap command `nmap -p- -sV $TARGET` to perform a port scan of the target IP address. The output shows that the host is up and running, with 65534 closed tcp ports (conn-refused). The open ports include port 80, which is commonly used for HTTP traffic.

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 14:06 CET
Nmap scan report for 10.129.189.68
Host is up (0.059s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
```

**Exploring the website**
At first the web seems quite simple having just a login panel. We then performed a web scan using the command `gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt` to identify potential directories and files on the target system. The command uses the `dirbuster` wordlist to find directory listings. The output shows the results of the web scan, including the URL, method, threads, wordlist, negative status codes, user agent, and timeout.
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.189.68
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/11/21 14:09:19 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.129.189.68/images/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.189.68/css/]   
/js                   (Status: 301) [Size: 311] [--> http://10.129.189.68/js/]    
/vendor               (Status: 301) [Size: 315] [--> http://10.129.189.68/vendor/]
                                                                                  
===============================================================
2023/11/21 14:25:27 Finished
===============================================================
```
There aren't any interesting finds.

Since we already have a form we can try to exploit it with a sql injecction, in this case we are going to use a manual one.
We try to enter in the username field the value: `admin'#`️

And bingo we get the desired flag.