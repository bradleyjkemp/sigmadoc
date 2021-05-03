---
title: "UAC Bypass via Sdclt"
aliases:
  - "/rule/5b872a46-3b90-45c1-8419-f675db8053aa"

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1088
  - attack.t1548.002
  - car.2019-04-001



date: Fri, 17 Mar 2017 14:31:26 -0400


---

Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand

<!--more-->


## Known false-positives

* unknown



## References

* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/


## Raw rule
```yaml
title: UAC Bypass via Sdclt
id: 5b872a46-3b90-45c1-8419-f675db8053aa
status: experimental
description: Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand
references:
    - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
author: Omer Yampel
date: 2017/03/17
modified: 2020/09/06
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        # usrclass.dat is mounted on HKU\USERSID_Classes\...
        TargetObject: 'HKU\\*_Classes\exefile\shell\runas\command\isolatedCommand'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088 # an old one
    - attack.t1548.002
    - car.2019-04-001
falsepositives:
    - unknown
level: high

```