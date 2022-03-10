---
title: "Disable PUA Protection on Windows Defender"
aliases:
  - "/rule/8ffc5407-52e3-478f-9596-0a7371eafe13"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 4 Aug 2021 11:27:41 -0500


---

Detects disabling Windows Defender PUA protection

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_disabled_pua_protection_on_microsoft_defender.yml))
```yaml
title: Disable PUA Protection on Windows Defender
id: 8ffc5407-52e3-478f-9596-0a7371eafe13
description: Detects disabling Windows Defender PUA protection
status: experimental
date: 2021/08/04
author: Austin Songer @austinsonger
references:
    - https://www.tenforums.com/tutorials/32236-enable-disable-microsoft-defender-pua-protection-windows-10-a.html
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Unknown
level: high

```
