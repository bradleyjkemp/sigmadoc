---
title: "DPAPI Domain Master Key Backup Attempt"
aliases:
  - "/rule/39a94fd1-8c9a-4ff6-bf22-c058762f8014"


tags:
  - attack.credential_access
  - attack.t1003.004



status: test





date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-190620024610.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_dpapi_domain_masterkey_backup_attempt.yml))
```yaml
title: DPAPI Domain Master Key Backup Attempt
id: 39a94fd1-8c9a-4ff6-bf22-c058762f8014
status: test
description: Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.
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
    EventID: 4692
  condition: selection
fields:
  - ComputerName
  - SubjectDomainName
  - SubjectUserName
falsepositives:
  - Unknown
level: critical
tags:
  - attack.credential_access
  - attack.t1003.004

```
