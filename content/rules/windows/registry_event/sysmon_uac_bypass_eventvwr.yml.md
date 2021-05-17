---
title: "UAC Bypass via Event Viewer"
aliases:
  - "/rule/7c81fec3-1c1d-43b0-996a-46753041b1b6"

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1088
  - attack.t1548.002
  - car.2019-04-001



status: experimental



level: critical



date: Sun, 19 Mar 2017 19:34:06 +0100


---

Detects UAC bypass method using Windows event viewer

<!--more-->


## Known false-positives

* unknown



## References

* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
* https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100


## Raw rule
```yaml
action: global
title: UAC Bypass via Event Viewer
id: 7c81fec3-1c1d-43b0-996a-46753041b1b6
status: experimental
description: Detects UAC bypass method using Windows event viewer
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100
author: Florian Roth
date: 2017/03/19
modified: 2020/09/06
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088 # an old one
    - attack.t1548.002
    - car.2019-04-001
falsepositives:
    - unknown
level: critical
---
logsource:
    product: windows
    category: registry_event
detection:
    methregistry:
        TargetObject: 'HKU\\*\mscfile\shell\open\command'
    condition: methregistry
---
logsource:
    category: process_creation
    product: windows
detection:
    methprocess:
        ParentImage: '*\eventvwr.exe'
    filterprocess:
        Image: '*\mmc.exe'
    condition: methprocess and not filterprocess
fields:
    - CommandLine
    - ParentCommandLine

```
