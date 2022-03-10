---
title: "LSASS Access from White-Listed Processes"
aliases:
  - "/rule/4be8b654-0c01-4c9d-a10c-6b28467fc651"


tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0002



status: experimental





date: Thu, 10 Feb 2022 09:17:25 +0100


---

Detects a possible process memory dump that uses the white-listed filename like TrolleyExpress.exe as a way to dump the lsass process memory without Microsoft Defender interference

<!--more-->


## Known false-positives

* Unlikely, since these tools shouldn't access lsass.exe at all



## References

* https://twitter.com/_xpn_/status/1491557187168178176
* https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
* https://twitter.com/mrd0x/status/1460597833917251595


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_lsass_memdump_evasion.yml))
```yaml
title: LSASS Access from White-Listed Processes
id: 4be8b654-0c01-4c9d-a10c-6b28467fc651
status: experimental
description: Detects a possible process memory dump that uses the white-listed filename like TrolleyExpress.exe as a way to dump the lsass process memory without Microsoft Defender interference
author: Florian Roth
references:
  - https://twitter.com/_xpn_/status/1491557187168178176
  - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
  - https://twitter.com/mrd0x/status/1460597833917251595
date: 2022/02/10
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: 
            - '\TrolleyExpress.exe'  # Citrix 
            - '\ProcessDump.exe'     # Cisco Jabber
            - '\dump64.exe'          # Visual Studio
        GrantedAccess|endswith:
            - '10'
            - '30'
            - '50'
            - '70'
            - '90'
            - 'B0'
            - 'D0'
            - 'F0'
            - '18'
            - '38'
            - '58'
            - '78'
            - '98'
            - 'B8'
            - 'D8'
            - 'F8'
            - '1A'
            - '3A'
            - '5A'
            - '7A'
            - '9A'
            - 'BA'
            - 'DA'
            - 'FA'
            - '0x14C2'  # https://github.com/b4rtik/ATPMiniDump/blob/master/ATPMiniDump/ATPMiniDump.c
            - 'FF'
    condition: selection
falsepositives:
    - Unlikely, since these tools shouldn't access lsass.exe at all
level: high
```