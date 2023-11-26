# Keeper
#activemachine
#crashdump
#easy
#publickey
### Reconnaissance
The recon phase involves gathering information about the target to identify potential vulnerabilities. In this case, we used the Nmap command `nmap -v -sV $TARGET` to perform a port scan of the target IP address. The output shows that the host is up and running, with 65534 closed tcp ports (conn-refused). The open ports include port 80, which is commonly used for HTTP traffic, and also the port 22 running SSH. 
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### Web Application Analysis
After the recon we can start by checking the website contents, after going to the IP web, the URL is modified and set as `keeper.htb`, also the web only says to go to `tickets.keeper.htb` so we add that domain and the upper one to /etc/hosts by running

`echo "${TARGET} tickets.keeper.htb" | sudo tee -a /etc/hosts`
`echo "${TARGET} keeper.htb" | sudo tee -a /etc/hosts`

In the new tab we see a login panel, so we research if there are any default credentials to this specific software by googling `request tracker default credentials`. It seems in fact that there are default credentials which are `root:password`

After logging in as root we can check all the users info, here we can find a user called `lnorgaard`  and also the user password which is `Welcome2023!`

Since we are inside a ticket platform, we  must check previously created/checked tickets, here we get information that we can use later on the pentest, there is a keypass crash dump in  `lnorgaard` home which can contain more useful information.

### Privilege escalation
Inside the home we find `user.txt` which contains the first flag and also we find `RT30000.zip`.
After unziping it we have a `KeePassDumpFull.dmp` and `passcodes.kdbx`, so we download both files with scp to our local machine.

In order to unlock the pass-codes we need the master password, so to get it we will use a tool that can extract it from the dump. The tool is the following [keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper) . Once it is installed we  just need to run `dotnet run ../KeePassDumpFull.dmp`. The master password is `M}dgrød med fløde`

After trying to use it, we realize it doesn't work so we google it and its a desert, we can try to use the original name
`rødgrød med fløde`, this time we unlock the keypass. Here the root password can be found but it doesnt work, anyways it also includes a PutTTy User Key that we can use.

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

After performing a little of research we can generate a SSH key using this and the program puttygen.
In windows you can open your key with the program and in the column of conversions export it as a openSSH key that you can use.

Now we just need to enter as root using the SSH key we just generated, to do so  `ssh -i a root@10.10.11.227`
The flag as usual is in `/root/root.txt`


