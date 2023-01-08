---
title: "UAC Bypass Abusing Winsat Path Parsing - Registry"
aliases:
  - "/rule/6597be7b-ac61-4ac8-bef4-d3ec88174853"
ruleid: 6597be7b-ac61-4ac8-bef4-d3ec88174853

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_uac_bypass_winsat.yml))
```yaml
title: UAC Bypass Abusing Winsat Path Parsing - Registry
id: 6597be7b-ac61-4ac8-bef4-d3ec88174853
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
author: Christian Burkard
date: 2021/08/30
modified: 2022/01/13
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: '\Root\InventoryApplicationFile\winsat.exe|'
        TargetObject|endswith: '\LowerCaseLongPath'
        Details|startswith: 'c:\users\'
        Details|endswith: '\appdata\local\temp\system32\winsat.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
