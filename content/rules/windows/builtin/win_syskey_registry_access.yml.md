---
title: "SysKey Registry Keys Access"
aliases:
  - "/rule/9a4ff3b8-6187-4fd2-8e8b-e0eae1129495"

tags:
  - attack.discovery
  - attack.t1012



status: experimental



level: critical



date: Thu, 24 Oct 2019 02:40:11 +0200


---

Detects handle requests and access operations to specific registry keys to calculate the SysKey

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md


## Raw rule
```yaml
title: SysKey Registry Keys Access
id: 9a4ff3b8-6187-4fd2-8e8b-e0eae1129495
description: Detects handle requests and access operations to specific registry keys to calculate the SysKey
status: experimental
date: 2019/08/12
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/hunters-forge/ThreatHunter-Playbook/blob/master/playbooks/windows/07_discovery/T1012_query_registry/syskey_registry_keys_access.md
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'key'
        ObjectName|endswith:
            - 'lsa\JD'
            - 'lsa\GBG'
            - 'lsa\Skew1'
            - 'lsa\Data'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
