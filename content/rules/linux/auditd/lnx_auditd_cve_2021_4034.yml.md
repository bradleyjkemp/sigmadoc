---
title: "CVE-2021-4034 Exploitation Attempt"
aliases:
  - "/rule/40a016ab-4f48-4eee-adde-bbf612695c53"
ruleid: 40a016ab-4f48-4eee-adde-bbf612695c53

tags:
  - attack.privilege_escalation
  - attack.t1068



status: experimental





date: Thu, 27 Jan 2022 12:36:19 +0100


---

Detects exploitation attempt of vulnerability described in CVE-2021-4034.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/berdav/CVE-2021-4034
* https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034
* https://access.redhat.com/security/cve/CVE-2021-4034


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_cve_2021_4034.yml))
```yaml
title: CVE-2021-4034 Exploitation Attempt
id: 40a016ab-4f48-4eee-adde-bbf612695c53
description: Detects exploitation attempt of vulnerability described in CVE-2021-4034.
author: 'Pawel Mazur'
status: experimental
date: 2022/01/27
references:
   - https://github.com/berdav/CVE-2021-4034
   - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4034
   - https://access.redhat.com/security/cve/CVE-2021-4034
logsource:
   product: linux
   service: auditd
detection:
    proctitle:
        type: PROCTITLE
        proctitle: '(null)'
    syscall:
       type: SYSCALL
       comm: pkexec 
       exe: '/usr/bin/pkexec'
    condition: proctitle and syscall
tags:
   - attack.privilege_escalation
   - attack.t1068
falsepositives:
   - unknown
level: high

```
