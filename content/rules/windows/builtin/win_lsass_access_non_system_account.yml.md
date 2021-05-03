---
title: "LSASS Access from Non System Account"
aliases:
  - "/rule/962fe167-e48d-4fd6-9974-11e5b9a5d6d1"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001



date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects potential mimikatz-like tools accessing LSASS from non system account

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/lsass_access_non_system_account.md


## Raw rule
```yaml
title: LSASS Access from Non System Account
id: 962fe167-e48d-4fd6-9974-11e5b9a5d6d1
description: Detects potential mimikatz-like tools accessing LSASS from non system account
status: experimental
date: 2019/06/20
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/lsass_access_non_system_account.md
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4663
            - 4656
        ObjectType: 'Process'
        ObjectName|endswith: '\lsass.exe'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
fields:
    - ComputerName
    - ObjectName
    - SubjectUserName
    - ProcessName
falsepositives:
    - Unknown
level: critical

```
