---
title: "LockerGoga Ransomware"
aliases:
  - "/rule/74db3488-fd28-480a-95aa-b7af626de068"
ruleid: 74db3488-fd28-480a-95aa-b7af626de068

tags:
  - attack.impact
  - attack.t1486



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects LockerGoga Ransomware command line.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://medium.com/@malwaredancer/lockergoga-input-arguments-ipc-communication-and-others-bd4e5a7ba80a
* https://blog.f-secure.com/analysis-of-lockergoga-ransomware/
* https://www.carbonblack.com/blog/tau-threat-intelligence-notification-lockergoga-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mal_lockergoga_ransomware.yml))
```yaml
title: LockerGoga Ransomware
id: 74db3488-fd28-480a-95aa-b7af626de068
status: test
description: Detects LockerGoga Ransomware command line.
author: Vasiliy Burov, oscd.community
references:
  - https://medium.com/@malwaredancer/lockergoga-input-arguments-ipc-communication-and-others-bd4e5a7ba80a
  - https://blog.f-secure.com/analysis-of-lockergoga-ransomware/
  - https://www.carbonblack.com/blog/tau-threat-intelligence-notification-lockergoga-ransomware/
date: 2020/10/18
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: '-i SM-tgytutrc -s'
  condition: selection
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.impact
  - attack.t1486

```
