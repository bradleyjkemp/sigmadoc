---
title: "Atbroker Registry Change"
aliases:
  - "/rule/9577edbb-851f-4243-8c91-1d5b50c1a39b"
ruleid: 9577edbb-851f-4243-8c91-1d5b50c1a39b

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.persistence
  - attack.t1547



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects creation/modification of Assisitive Technology applications and persistence with usage of ATs

<!--more-->


## Known false-positives

* Creation of non-default, legitimate AT.



## References

* http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Atbroker.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_susp_atbroker_change.yml))
```yaml
title: Atbroker Registry Change
id: 9577edbb-851f-4243-8c91-1d5b50c1a39b
description: Detects creation/modification of Assisitive Technology applications and persistence with usage of ATs
status: experimental
author: Mateusz Wydra, oscd.community
references:
    - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Atbroker.yml
date: 2020/10/13
modified: 2021/05/24
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.persistence
    - attack.t1547
logsource:
    category: registry_event
    product: windows
detection:
    creation:
        TargetObject|contains: 'Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs'
    persistence:
        TargetObject|contains: 'Software\Microsoft\Windows NT\CurrentVersion\Accessibility\Configuration'
    condition: creation or persistence
falsepositives:
    - Creation of non-default, legitimate AT.
level: high

```