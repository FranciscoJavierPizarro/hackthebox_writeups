# Fawn
#startingpoint 
#veryeasy 
#ftp

Firstly, we start by opening a VPN connection and launching the VM on HTB.
### Reconnaissance
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.47. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there is one open port, TCP port 21, which is running a ftp service.
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-16 11:24 CET
Nmap scan report for 10.129.193.47
Host is up (0.051s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
Service Info: OS: Unix
```
### FTP Protocol
Since we found an open port, we try to connect to it using the `ftp` command. The system does not ask for credentials when we attempt to connect as anonymous. This suggests that the FTP service is not secure and we can try to exploit it further.
```
ftp $TARGET
```
```
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Now that we are in we can search the files that are inside this FTP server and get the ones that we need, in this case we want the flag.txt so we download it with the `get` command
```
ls
get flag.txt
```