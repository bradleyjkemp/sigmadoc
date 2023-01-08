---
title: "Registry Entries For Azorult Malware"
aliases:
  - "/rule/f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7"
ruleid: f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7

tags:
  - attack.execution
  - attack.t1112



status: test





date: Fri, 8 May 2020 21:26:24 -0400


---

Detects the presence of a registry key created during Azorult execution

<!--more-->


## Known false-positives

* unknown



## References

* https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_mal_azorult.yml))
```yaml
title: Registry Entries For Azorult Malware
id: f7f9ab88-7557-4a69-b30e-0a8f91b3a0e7
status: test
description: Detects the presence of a registry key created during Azorult execution
author: Trent Liffick
references:
  - https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.azoruit.a
date: 2020/05/08
modified: 2021/11/27
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    EventID:
      - 12
      - 13
    TargetObject|contains: 'SYSTEM\'
    TargetObject|endswith: '\services\localNETService'
  condition: selection
fields:
  - Image
  - TargetObject
  - TargetDetails
falsepositives:
  - unknown
level: critical
tags:
  - attack.execution
  - attack.t1112

```
