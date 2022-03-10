---
title: "SAM Registry Hive Handle Request"
aliases:
  - "/rule/f8748f2c-89dc-4d95-afb0-5a2dfdbad332"


tags:
  - attack.discovery
  - attack.t1012
  - attack.credential_access
  - attack.t1552.002



status: test





date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects handles requested to SAM registry hive

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190725024610.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_sam_registry_hive_handle_request.yml))
```yaml
title: SAM Registry Hive Handle Request
id: f8748f2c-89dc-4d95-afb0-5a2dfdbad332
status: test
description: Detects handles requested to SAM registry hive
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190725024610.html
date: 2019/08/12
modified: 2021/11/27
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
tags:
  - attack.discovery
  - attack.t1012
  - attack.credential_access
  - attack.t1552.002

```
