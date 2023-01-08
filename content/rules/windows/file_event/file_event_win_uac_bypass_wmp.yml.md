---
title: "UAC Bypass Using Windows Media Player - File"
aliases:
  - "/rule/68578b43-65df-4f81-9a9b-92f32711a951"
ruleid: 68578b43-65df-4f81-9a9b-92f32711a951

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_wmp.yml))
```yaml
title: UAC Bypass Using Windows Media Player - File
id: 68578b43-65df-4f81-9a9b-92f32711a951
description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
author: Christian Burkard
date: 2021/08/23
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
    selection1:
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|endswith: '\AppData\Local\Temp\OskSupport.dll'
    selection2:
        Image: 'C:\Windows\system32\DllHost.exe'
        TargetFilename: 'C:\Program Files\Windows Media Player\osk.exe'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```
