---
title: "LSASS Memory Access by Tool Named Dump"
aliases:
  - "/rule/9bd012ee-0dff-44d7-84a0-aa698cfd87a3"
ruleid: 9bd012ee-0dff-44d7-84a0-aa698cfd87a3

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0002



status: experimental





date: Thu, 10 Feb 2022 09:17:25 +0100


---

Detects a possible process memory dump based on a keyword in the file name of the accessing process

<!--more-->


## Known false-positives

* Rare programs that contain the word dump in their name and access lsass



## References

* https://twitter.com/_xpn_/status/1491557187168178176
* https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_lsass_memdump_indicators.yml))
```yaml
title: LSASS Memory Access by Tool Named Dump
id: 9bd012ee-0dff-44d7-84a0-aa698cfd87a3
status: experimental
description: Detects a possible process memory dump based on a keyword in the file name of the accessing process
author: Florian Roth
references:
  - https://twitter.com/_xpn_/status/1491557187168178176
  - https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz
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
        SourceImage|contains: 'dump'
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
    - Rare programs that contain the word dump in their name and access lsass
level: high
```