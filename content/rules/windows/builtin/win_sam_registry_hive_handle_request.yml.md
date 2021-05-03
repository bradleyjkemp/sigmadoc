---
title: "SAM Registry Hive Handle Request"
aliases:
  - "/rule/f8748f2c-89dc-4d95-afb0-5a2dfdbad332"

tags:
  - attack.discovery
  - attack.t1012
  - attack.credential_access
  - attack.t1552.002



date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects handles requested to SAM registry hive

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md


## Raw rule
```yaml
title: SAM Registry Hive Handle Request
id: f8748f2c-89dc-4d95-afb0-5a2dfdbad332
description: Detects handles requested to SAM registry hive
status: experimental
date: 2019/08/12
modified: 2020/08/23
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md
tags:
    - attack.discovery
    - attack.t1012
    - attack.credential_access
    - attack.t1552.002
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'Key'
        ObjectName|endswith: '\SAM'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ProcessName
    - ObjectName
falsepositives:
    - Unknown
level: critical

```