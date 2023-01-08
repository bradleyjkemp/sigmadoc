---
title: "Office Application Startup - Office Test"
aliases:
  - "/rule/3d27f6dd-1c74-4687-b4fa-ca849d128d1c"
ruleid: 3d27f6dd-1c74-4687-b4fa-ca849d128d1c

tags:
  - attack.persistence
  - attack.t1137.002



status: experimental





date: Sun, 25 Oct 2020 12:36:08 +0530


---

Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started

<!--more-->


## Known false-positives

* Unlikely



## References

* https://attack.mitre.org/techniques/T1137/002/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_office_test_regadd.yml))
```yaml
title: Office Application Startup - Office Test
id: 3d27f6dd-1c74-4687-b4fa-ca849d128d1c
status: experimental
description: Detects the addition of office test registry that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started
references:
    - https://attack.mitre.org/techniques/T1137/002/
author: omkar72
tags:
    - attack.persistence
    - attack.t1137.002
date: 2020/10/25
modified: 2021/09/13
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        TargetObject:
            - 'HKCU\Software\Microsoft\Office test\Special\Perf'
            - 'HKLM\Software\Microsoft\Office test\Special\Perf'
    condition: selection_registry
falsepositives:
    - Unlikely
level: medium

```
