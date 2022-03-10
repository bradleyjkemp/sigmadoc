---
title: "Disable Microsoft Office Security Features"
aliases:
  - "/rule/7c637634-c95d-4bbf-b26c-a82510874b34"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Disable Microsoft Office Security Features by registry

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
* https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
* https://yoroi.company/research/cyber-criminal-espionage-operation-insists-on-italian-manufacturing/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_disable_microsoft_office_security_features.yml))
```yaml
title: Disable Microsoft Office Security Features
id: 7c637634-c95d-4bbf-b26c-a82510874b34
description: Disable Microsoft Office Security Features by registry
status: experimental
date: 2021/06/08
author: frack113
tags:
    - attack.defense_evasion
    - attack.t1562.001
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
    - https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
    - https://yoroi.company/research/cyber-criminal-espionage-operation-insists-on-italian-manufacturing/

logsource:
    product: windows
    category: registry_event
    definition: key must be add to the sysmon configuration to works
                    # Sysmon
                    # <TargetObject name="T1562,office" condition="end with">\VBAWarnings</TargetObject> 
                    # <TargetObject name="T1562,office" condition="end with">\DisableInternetFilesInPV</TargetObject>
                    # <TargetObject name="T1562,office" condition="end with">\DisableUnsafeLocationsInPV</TargetObject> 
                    # <TargetObject name="T1562,office" condition="end with">\DisableAttachementsInPV</TargetObject>   
detection:
    selection:
        EventType: SetValue
        TargetObject|contains: '\SOFTWARE\Microsoft\Office\'
        TargetObject|endswith:
            - VBAWarnings
            - DisableInternetFilesInPV
            - DisableUnsafeLocationsInPV
            - DisableAttachementsInPV
        Details: 'DWORD (0x00000001)'
    condition: selection
falsepositives:
    - unknown
level: high

```
