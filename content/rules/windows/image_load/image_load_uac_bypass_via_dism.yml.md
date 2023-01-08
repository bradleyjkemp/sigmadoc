---
title: "UAC Bypass With Fake DLL"
aliases:
  - "/rule/a5ea83a7-05a5-44c1-be2e-addccbbd8c03"
ruleid: a5ea83a7-05a5-44c1-be2e-addccbbd8c03

tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002
  - attack.t1574.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Attempts to load dismcore.dll after dropping it

<!--more-->


## Known false-positives

* Pentests
* Actions of a legitimate telnet client



## References

* https://steemit.com/utopian-io/@ah101/uac-bypassing-utility


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_uac_bypass_via_dism.yml))
```yaml
title: UAC Bypass With Fake DLL
id: a5ea83a7-05a5-44c1-be2e-addccbbd8c03
status: experimental
description: Attempts to load dismcore.dll after dropping it
references:
    - https://steemit.com/utopian-io/@ah101/uac-bypassing-utility
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
    - attack.t1574.002
author: oscd.community, Dmitry Uchakin
date: 2020/10/06
modified: 2021/11/23
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith:
            - '\dism.exe'
        ImageLoaded|endswith:
            - '\dismcore.dll'
    filter:
        ImageLoaded:
            - 'C:\Windows\System32\Dism\dismcore.dll'
    condition: selection and not filter
falsepositives:
    - Pentests
    - Actions of a legitimate telnet client
level: high

```
