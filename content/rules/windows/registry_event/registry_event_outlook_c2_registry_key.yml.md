---
title: "Outlook C2 Registry Key"
aliases:
  - "/rule/e3b50fa5-3c3f-444e-937b-0a99d33731cd"


tags:
  - attack.persistence
  - attack.command_and_control
  - attack.t1137
  - attack.t1008
  - attack.t1546



status: experimental





date: Tue, 20 Apr 2021 20:38:20 -0400


---

Detects the modification of Outlook Security Setting to allow unprompted execution. Goes with win_outlook_c2_macro_creation.yml and is particularly interesting if both events occur near to each other.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_outlook_c2_registry_key.yml))
```yaml
title: Outlook C2 Registry Key
id: e3b50fa5-3c3f-444e-937b-0a99d33731cd
status: experimental
description: Detects the modification of Outlook Security Setting to allow unprompted execution. Goes with win_outlook_c2_macro_creation.yml and is particularly interesting if both events occur near to each other.
references:
    - https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/
author: '@ScoubiMtl'
tags:
    - attack.persistence
    - attack.command_and_control
    - attack.t1137
    - attack.t1008
    - attack.t1546
date: 2021/04/05
modified: 2022/01/13
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        EventType: SetValue 
        TargetObject: 'HKCU\Software\Microsoft\Office\16.0\Outlook\Security\Level'
        Details|contains: '0x00000001'
    condition: selection_registry
falsepositives:
    - Unlikely
level: medium

```
