---
title: "DPAPI Domain Master Key Backup Attempt"
aliases:
  - "/rule/39a94fd1-8c9a-4ff6-bf22-c058762f8014"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.004



date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md


## Raw rule
```yaml
title: DPAPI Domain Master Key Backup Attempt
id: 39a94fd1-8c9a-4ff6-bf22-c058762f8014
description: Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.
status: experimental
date: 2019/08/10
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
        EventID: 4692
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
falsepositives:
    - Unknown
level: critical

```