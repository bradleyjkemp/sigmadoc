---
title: "CVE-2021-3156 Exploitation Attempt"
aliases:
  - "/rule/5ee37487-4eb8-4ac2-9be1-d7d14cdc559f"


tags:
  - attack.privilege_escalation
  - attack.t1068
  - cve.2021.3156



status: experimental





date: Mon, 1 Feb 2021 23:08:45 +0545


---

Detects exploitation attempt of vulnerability described in CVE-2021-3156. | Alternative approach might be to look for flooding of auditd logs due to bruteforcing | required to trigger the heap-based buffer overflow.

<!--more-->


## Known false-positives

* Unknown



## References

* https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_cve_2021_3156_sudo_buffer_overflow.yml))
```yaml
title: CVE-2021-3156 Exploitation Attempt
id: 5ee37487-4eb8-4ac2-9be1-d7d14cdc559f
status: experimental
description: Detects exploitation attempt of vulnerability described in CVE-2021-3156. |
             Alternative approach might be to look for flooding of auditd logs due to bruteforcing |
             required to trigger the heap-based buffer overflow.
author: Bhabesh Raj
date: 2021/02/01
modified: 2021/09/14
references:
    - https://blog.qualys.com/vulnerabilities-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit
tags:
    - attack.privilege_escalation
    - attack.t1068
    - cve.2021.3156
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0: '/usr/bin/sudoedit'
    cmd1:
        a1: '-s'
    cmd2:
        a2: '-s'
    cmd3:
        a3: '-s'
    cmd4:
        a4: '-s'
    cmd5:
        a1: '\'
    cmd6:
        a2: '\'
    cmd7:
        a3: '\'
    cmd8:
        a4: '\'
    condition: selection and (cmd1 or cmd2 or cmd3 or cmd4) and (cmd5 or cmd6 or cmd7 or cmd8) | count() by host > 50
falsepositives:
    - Unknown
level: critical
```
