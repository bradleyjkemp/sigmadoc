---
title: "UAC Bypass Using IEInstal - File"
aliases:
  - "/rule/bdd8157d-8e85-4397-bb82-f06cc9c71dbb"
ruleid: bdd8157d-8e85-4397-bb82-f06cc9c71dbb

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_ieinstal.yml))
```yaml
title: UAC Bypass Using IEInstal - File
id: bdd8157d-8e85-4397-bb82-f06cc9c71dbb
description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
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
        Image: 'C:\Program Files\Internet Explorer\IEInstal.exe'
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|contains: '\AppData\Local\Temp\'
        TargetFilename|endswith: 'consent.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
