---
title: "Protected Storage Service Access"
aliases:
  - "/rule/45545954-4016-43c6-855e-eae8f1c369dc"

tags:
  - attack.lateral_movement
  - attack.t1021
  - attack.t1021.002



date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md


## Raw rule
```yaml
title: Protected Storage Service Access
id: 45545954-4016-43c6-855e-eae8f1c369dc
description: Detects access to a protected_storage service over the network. Potential abuse of DPAPI to extract domain backup keys from Domain Controllers
status: experimental
date: 2019/08/10
modified: 2020/08/23
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.lateral_movement
    - attack.t1021          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 5145
        ShareName|contains: 'IPC'
        RelativeTargetName: "protected_storage"
    condition: selection
falsepositives:
    - Unknown
level: critical
```
