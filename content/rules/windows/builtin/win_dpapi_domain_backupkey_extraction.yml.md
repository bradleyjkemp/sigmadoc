---
title: "DPAPI Domain Backup Key Extraction"
aliases:
  - "/rule/4ac1f50b-3bd0-4968-902d-868b4647937e"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.004



date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md


## Raw rule
```yaml
title: DPAPI Domain Backup Key Extraction
id: 4ac1f50b-3bd0-4968-902d-868b4647937e
description: Detects tools extracting LSA secret DPAPI domain backup key from Domain Controllers
status: experimental
date: 2019/06/20
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.004
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        ObjectType: 'SecretObject'
        AccessMask: '0x2'
        ObjectName: 'BCKUPKEY'
    condition: selection
falsepositives:
    - Unknown
level: critical

```