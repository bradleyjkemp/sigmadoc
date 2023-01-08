---
title: "Password Policy Discovery"
aliases:
  - "/rule/ca94a6db-8106-4737-9ed2-3e3bb826af0a"
ruleid: ca94a6db-8106-4737-9ed2-3e3bb826af0a

tags:
  - attack.discovery
  - attack.t1201



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects password policy discovery commands

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md
* https://attack.mitre.org/techniques/T1201/
* https://linux.die.net/man/1/chage
* https://man7.org/linux/man-pages/man1/passwd.1.html
* https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_password_policy_discovery.yml))
```yaml
title: Password Policy Discovery
id: ca94a6db-8106-4737-9ed2-3e3bb826af0a
status: stable
description: Detects password policy discovery commands
author: Ömer Günal, oscd.community, Pawel Mazur
date: 2020/10/08
modified: 2021/11/12
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1201/T1201.md
    - https://attack.mitre.org/techniques/T1201/
    - https://linux.die.net/man/1/chage
    - https://man7.org/linux/man-pages/man1/passwd.1.html
    - https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu
logsource:
    product: linux
    service: auditd
detection:
    files:
      type: 'PATH'
      name:
          - '/etc/pam.d/common-password'
          - '/etc/security/pwquality.conf'
          - '/etc/pam.d/system-auth'
          - '/etc/login.defs'
    chage: 
      type: 'EXECVE'
      a0: 'chage'
      a1: 
         - '--list'
         - '-l'
    passwd:
      type: 'EXECVE'
      a0: 'passwd'
      a1: 
         - '-S'
         - '--status'
    condition: files or chage or passwd
falsepositives:
    - Legitimate administration activities
level: low
tags:
    - attack.discovery
    - attack.t1201

```
