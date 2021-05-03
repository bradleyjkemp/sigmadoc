---
title: "Cred Dump Tools Dropped Files"
aliases:
  - "/rule/8fbf3271-1ef6-4e94-8210-03c2317947f6"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.003
  - attack.t1003.004
  - attack.t1003.005



date: Mon, 4 Nov 2019 04:26:34 +0300


---

Files with well-known filenames (parts of credential dump software or files produced by them) creation

<!--more-->


## Known false-positives

* Legitimate Administrator using tool for password recovery



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule
```yaml
title: Cred Dump Tools Dropped Files
id: 8fbf3271-1ef6-4e94-8210-03c2317947f6
description: Files with well-known filenames (parts of credential dump software or files produced by them) creation
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
modified: 2020/08/23
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003         # an old one
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.003
    - attack.t1003.004
    - attack.t1003.005
logsource:
    category: file_event
    product: windows
detection:
    selection:        
        TargetFilename|contains: 
            - '\pwdump'
            - '\kirbi'
            - '\pwhashes'
            - '\wce_ccache'
            - '\wce_krbtkts'
            - '\fgdump-log'
        TargetFilename|endswith: 
            - '\test.pwd'
            - '\lsremora64.dll'
            - '\lsremora.dll'
            - '\fgexec.exe'
            - '\wceaux.dll'
            - '\SAM.out'
            - '\SECURITY.out'
            - '\SYSTEM.out'
            - '\NTDS.out'
            - '\DumpExt.dll'
            - '\DumpSvc.exe'
            - '\cachedump64.exe'
            - '\cachedump.exe'
            - '\pstgdump.exe'
            - '\servpw.exe'
            - '\servpw64.exe'
            - '\pwdump.exe'
            - '\procdump64.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: high
status: experimental

```