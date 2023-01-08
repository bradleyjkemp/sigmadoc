---
title: "PowerShell as a Service in Registry"
aliases:
  - "/rule/4a5f5a5e-ac01-474b-9b4e-d61298c9df1d"
ruleid: 4a5f5a5e-ac01-474b-9b4e-d61298c9df1d

tags:
  - attack.execution
  - attack.t1569.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects that a powershell code is written to the registry as a service.

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_powershell_as_service.yml))
```yaml
title: PowerShell as a Service in Registry
id: 4a5f5a5e-ac01-474b-9b4e-d61298c9df1d
description: Detects that a powershell code is written to the registry as a service.
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/06
modified: 2022/01/13
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse
tags:
    - attack.execution
    - attack.t1569.002
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue 
        TargetObject|contains: '\Services\'
        TargetObject|endswith: '\ImagePath'
        Details|contains:
          - 'powershell'
          - 'pwsh'
    condition: selection
falsepositives: 
 - Unknown
level: high

```
