---
title: "SCM Database Privileged Operation"
aliases:
  - "/rule/dae8171c-5ec6-4396-b210-8466585b53e9"



status: experimental



level: critical



date: Thu, 24 Oct 2019 02:40:11 +0200


---

Detects non-system users performing privileged operation os the SCM database

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md


## Raw rule
```yaml
title: SCM Database Privileged Operation
id: dae8171c-5ec6-4396-b210-8466585b53e9
description: Detects non-system users performing privileged operation os the SCM database
status: experimental
date: 2019/08/15
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4674
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'servicesactive'
        PrivilegeList: 'SeTakeOwnershipPrivilege'
        SubjectLogonId: "0x3e4"
    condition: selection
falsepositives:
    - Unknown
level: critical

```
