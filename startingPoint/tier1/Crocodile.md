 #veryeasy 
 #ftp 
 #web 

**Reconnaissance**
The `nmap -p- -sV -sC $TARGET` command was used to scan the target host for open ports and services. Nmap is a powerful tool for network exploration and security auditing. In this case, we used the `-p-` option to specify that we want to scan the host for both TCP and UDP ports. The `-sV` option tells nmap to perform a version detection scan, while the `-sC` option tells it to perform a connect scan. The output shows us that the host is running an FTP server (vsftpd) and an Apache web server (Apache httpd). We also see that there are two files in the FTP server's root directory: `allowed.userlist` and `allowed.userlist.passwd`.
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 14:45 CET
Nmap scan report for 10.129.133.75
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.169
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Smash - Bootstrap Business Template
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 235.87 seconds
```

**FTP**
The `ftp $target` command was used to connect to the FTP server and list its contents. We saw two files in the directory: `allowed.userlist` and `allowed.userlist.passwd`. The `get` command was used to download both files, which contained a list of usernames and their corresponding passwords. To enter without a password we use the username `anonymous`
```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
226 Directory send OK.

ftp> get allowed.userlist
local: allowed.userlist remote: allowed.userlist
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist (33 bytes).
226 Transfer complete.
33 bytes received in 0.01 secs (6.0124 kB/s)

ftp> get allowed.userlist.passwd
local: allowed.userlist.passwd remote: allowed.userlist.passwd
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for allowed.userlist.passwd (62 bytes).
226 Transfer complete.
62 bytes received in 0.01 secs (7.0264 kB/s)
```

Based on the information we gathered from the FTP server, we can try to use the credentials we obtained to see if we can gain elevated privileges on the FTP server. After testing it we confirm that we cant, so now we need to explore other paths.

**Exploring the website**
We enter the website using the following URL  `http://10.129.133.75/`, once in at first sight we don't see nothing relevant, so now we perform a directory enumeration with `gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html`. The output shows us a list of files and directories on the target host, including the `index.html`, `login.php`, and `config.php` files.

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.133.75
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2023/11/21 14:54:48 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 58565]
/login.php            (Status: 200) [Size: 1577] 
/assets               (Status: 301) [Size: 315] [--> http://10.129.133.75/assets/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.133.75/css/]   
/js                   (Status: 301) [Size: 311] [--> http://10.129.133.75/js/]    
/logout.php           (Status: 302) [Size: 0] [--> login.php]                     
/config.php           (Status: 200) [Size: 0]                                     
/fonts                (Status: 301) [Size: 314] [--> http://10.129.133.75/fonts/] 
/dashboard            (Status: 301) [Size: 318] [--> http://10.129.133.75/dashboard/]
...
```
The most interesting finding is the login so we access it in our web-browser using as URL `http://10.129.133.75/login.php`. Now we can test another time the admin account credentials and bingo this time we get the flag.