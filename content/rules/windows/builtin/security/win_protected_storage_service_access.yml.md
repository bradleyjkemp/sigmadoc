---
title: "Protected Storage Service Access"
aliases:
  - "/rule/45545954-4016-43c6-855e-eae8f1c369dc"
ruleid: 45545954-4016-43c6-855e-eae8f1c369dc

tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-190620024610.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_protected_storage_service_access.yml))
```yaml
title: Protected Storage Service Access
id: 45545954-4016-43c6-855e-eae8f1c369dc
status: test
description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-190620024610.html
date: 2019/08/10
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 5145
    ShareName|contains: 'IPC'
    RelativeTargetName: 'protected_storage'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.lateral_movement
  - attack.t1021.002

```
