---
title: "Sudo Privilege Escalation CVE-2019-14287"
aliases:
  - "/rule/f74107df-b6c6-4e80-bf00-4170b658162b"

tags:
  - attack.privilege_escalation
  - attack.t1068
  - attack.t1169



date: Tue, 15 Oct 2019 09:39:08 +0200


---

Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.openwall.com/lists/oss-security/2019/10/14/1
* https://access.redhat.com/security/cve/cve-2019-14287
* https://twitter.com/matthieugarin/status/1183970598210412546


## Raw rule
```yaml
action: global
title: Sudo Privilege Escalation CVE-2019-14287
id: f74107df-b6c6-4e80-bf00-4170b658162b
status: experimental
description: Detects users trying to exploit sudo vulnerability reported in CVE-2019-14287
author: Florian Roth
date: 2019/10/15
modified: 2019/10/20
references:
    - https://www.openwall.com/lists/oss-security/2019/10/14/1
    - https://access.redhat.com/security/cve/cve-2019-14287
    - https://twitter.com/matthieugarin/status/1183970598210412546
logsource:
    product: linux
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.t1169
---
detection:
    selection_keywords:
        - '* -u#*'
    condition: selection_keywords
--- 
detection:
    selection_user:
        USER:
            - '#-*'
            - '#*4294967295'
    condition: selection_user
```