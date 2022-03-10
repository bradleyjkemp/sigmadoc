---
title: "UAC Bypass Using NTFS Reparse Point - Process"
aliases:
  - "/rule/39ed3c80-e6a1-431b-9df3-911ac53d08a7"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_ntfs_reparse_point.yml))
```yaml
title: UAC Bypass Using NTFS Reparse Point - Process
id: 39ed3c80-e6a1-431b-9df3-911ac53d08a7
description: Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)
author: Christian Burkard
date: 2021/08/30
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|startswith: '"C:\Windows\system32\wusa.exe"  /quiet C:\Users\'
        CommandLine|endswith: '\AppData\Local\Temp\update.msu'
        IntegrityLevel:
          - 'High'
          - 'System'
    selection2:
        ParentCommandLine: '"C:\Windows\system32\dism.exe" /online /quiet /norestart /add-package /packagepath:"C:\Windows\system32\pe386" /ignorecheck'
        IntegrityLevel:
          - 'High'
          - 'System'
        CommandLine|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\dismhost.exe {'
        Image|endswith: '\DismHost.exe'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```
