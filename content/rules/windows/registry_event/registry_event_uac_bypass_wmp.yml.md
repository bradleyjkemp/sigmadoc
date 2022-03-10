---
title: "UAC Bypass Using Windows Media Player - Registry"
aliases:
  - "/rule/5f9db380-ea57-4d1e-beab-8a2d33397e93"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_uac_bypass_wmp.yml))
```yaml
title: UAC Bypass Using Windows Media Player - Registry
id: 5f9db380-ea57-4d1e-beab-8a2d33397e93
description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
author: Christian Burkard
date: 2021/08/23
modified: 2022/01/13
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|endswith: '\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store\C:\Program Files\Windows Media Player\osk.exe'
        Details: 'Binary Data'
    condition: selection
falsepositives:
    - Unknown
level: high

```
