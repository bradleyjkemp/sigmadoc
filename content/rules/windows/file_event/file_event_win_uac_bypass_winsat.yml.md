---
title: "UAC Bypass Abusing Winsat Path Parsing - File"
aliases:
  - "/rule/155dbf56-e0a4-4dd0-8905-8a98705045e8"
ruleid: 155dbf56-e0a4-4dd0-8905-8a98705045e8

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_winsat.yml))
```yaml
title: UAC Bypass Abusing Winsat Path Parsing - File
id: 155dbf56-e0a4-4dd0-8905-8a98705045e8
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
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
        TargetFilename|endswith:
            - '\AppData\Local\Temp\system32\winsat.exe'
            - '\AppData\Local\Temp\system32\winmm.dll'
    condition: selection
falsepositives:
    - Unknown
level: high

```
