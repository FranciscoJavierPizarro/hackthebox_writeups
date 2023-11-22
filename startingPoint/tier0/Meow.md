#veryeasy 
#telnet

Firstly, we start by opening a VPN connection and launching the VM on HTB.

**Reconnaissance**
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.6. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there is one open port, TCP port 23, which is likely to be a telnet service.
```
Starting Nmap 7.93 (https://nmap.org) at 2023-11-16 11:15 CET
Nmap scan report for 10.129.193.6
Host is up (0.046s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Telnet Protocol**
Since we found an open port, we try to connect to it using the `telnet` command. We enter the target host's IP address. However, we encounter a problem - the system does not ask for credentials when we attempt to connect as root. This suggests that the telnet service is not secure and we can try to exploit it further.
```
telnet $TARGET
```
**Terminal Access**
We are now in a terminal session on the target host, which allows us to execute commands and potentially escalate privileges. We use the `ls` command to list the files and directories in the current directory, and then check the contents of a file named `flag.txt`.
```
ls
cat flag.txt
```
The output of these commands will reveal the flag value that we were searching.️