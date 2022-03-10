---
title: "Disable UAC Using Registry"
aliases:
  - "/rule/48437c39-9e5f-47fb-af95-3d663c3f2919"


tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002



status: experimental





date: Wed, 5 Jan 2022 19:52:52 +0100


---

Disable User Account Conrol (UAC) by changing its registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA from 1 to 0

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-8---disable-uac-using-regexe


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_disable_uac_registry.yml))
```yaml
title: Disable UAC Using Registry
id: 48437c39-9e5f-47fb-af95-3d663c3f2919
description: Disable User Account Conrol (UAC) by changing its registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA from 1 to 0
author: frack113
date: 2022/01/05
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1548.002/T1548.002.md#atomic-test-8---disable-uac-using-regexe
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
        Details: DWORD (0x00000000)
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1548.002

```
