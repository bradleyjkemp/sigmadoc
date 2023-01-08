---
title: "UAC Bypass via Sdclt"
aliases:
  - "/rule/5b872a46-3b90-45c1-8419-f675db8053aa"
ruleid: 5b872a46-3b90-45c1-8419-f675db8053aa

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002
  - car.2019-04-001



status: experimental





date: Fri, 17 Mar 2017 14:31:26 -0400


---

Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe (e.g. UACMe 53)

<!--more-->


## Known false-positives

* unknown



## References

* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_uac_bypass_sdclt.yml))
```yaml
title: UAC Bypass via Sdclt
id: 5b872a46-3b90-45c1-8419-f675db8053aa
status: experimental
description: Detects the pattern of UAC Bypass using registry key manipulation of sdclt.exe (e.g. UACMe 53)
references:
    - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
    - https://github.com/hfiref0x/UACME
author: Omer Yampel, Christian Burkard
date: 2017/03/17
modified: 2022/01/13
logsource:
    category: registry_event
    product: windows
detection:
    selection1:
        TargetObject|endswith: Software\Classes\exefile\shell\runas\command\isolatedCommand
    selection2:
        EventType: SetValue 
        TargetObject|endswith: Software\Classes\Folder\shell\open\command\SymbolicLinkValue
        Details|contains: '-1???\Software\Classes\'
    condition: 1 of selection*
falsepositives:
    - unknown
level: high
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
    - car.2019-04-001
```
