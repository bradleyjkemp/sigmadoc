---
title: "NetNTLM Downgrade Attack"
aliases:
  - "/rule/d67572a0-e2ec-45d6-b8db-c100d14b8ef2"

tags:
  - attack.defense_evasion
  - attack.t1089
  - attack.t1562.001
  - attack.t1112



date: Tue, 20 Mar 2018 11:07:21 +0100


---

Detects NetNTLM downgrade attack

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks


## Raw rule
```yaml
action: global
title: NetNTLM Downgrade Attack
id: d67572a0-e2ec-45d6-b8db-c100d14b8ef2
description: Detects NetNTLM downgrade attack
references:
    - https://www.optiv.com/blog/post-exploitation-using-netntlm-downgrade-attacks
author: Florian Roth
date: 2018/03/20
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.001
    - attack.t1112
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        EventID: 13
        TargetObject: 
            - '*SYSTEM\\*ControlSet*\Control\Lsa\lmcompatibilitylevel'
            - '*SYSTEM\\*ControlSet*\Control\Lsa*\NtlmMinClientSec'
            - '*SYSTEM\\*ControlSet*\Control\Lsa*\RestrictSendingNTLMTraffic'
---
# Windows Security Eventlog: Process Creation with Full Command Line
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Object Access > Audit Registry (Success)'
detection:
    selection2:
        EventID: 4657
        ObjectName: '\REGISTRY\MACHINE\SYSTEM\\*ControlSet*\Control\Lsa*'
        ObjectValueName: 
            - 'LmCompatibilityLevel'
            - 'NtlmMinClientSec'
            - 'RestrictSendingNTLMTraffic'

```
