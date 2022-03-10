---
title: "UAC Bypass Using NTFS Reparse Point - File"
aliases:
  - "/rule/7fff6773-2baa-46de-a24a-b6eec1aba2d1"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_ntfs_reparse_point.yml))
```yaml
title: UAC Bypass Using NTFS Reparse Point - File
id: 7fff6773-2baa-46de-a24a-b6eec1aba2d1
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
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|endswith: '\AppData\Local\Temp\api-ms-win-core-kernel32-legacy-l1.DLL'
    condition: selection
falsepositives:
    - Unknown
level: high

```
