---
title: "Accessing WinAPI in PowerShell for Credentials Dumping"
aliases:
  - "/rule/3f07b9d1-2082-4c56-9277-613a621983cc"
ruleid: 3f07b9d1-2082-4c56-9277-613a621983cc

tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Accessing to lsass.exe by Powershell

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/sysmon/sysmon_accessing_winapi_in_powershell_credentials_dumping.yml))
```yaml
title: Accessing WinAPI in PowerShell for Credentials Dumping
id: 3f07b9d1-2082-4c56-9277-613a621983cc
description: Detects Accessing to lsass.exe by Powershell
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/06
modified: 2021/05/24
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
    product: windows
    service: sysmon
detection:
    selection:
      EventID:
        - 8
        - 10
      SourceImage|endswith: '\powershell.exe'
      TargetImage|endswith: '\lsass.exe'
    condition: selection
falsepositives: 
 - Unknown
level: high

```
