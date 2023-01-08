---
title: "Webshell Remote Command Execution"
aliases:
  - "/rule/c0d3734d-330f-4a03-aae2-65dacc6a8222"
ruleid: c0d3734d-330f-4a03-aae2-65dacc6a8222

tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Mon, 21 Oct 2019 11:14:24 +0200


---

Detects possible command execution by web application/web shell

<!--more-->


## Known false-positives

* Admin activity
* Crazy web applications



## References

* personal experience


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_web_rce.yml))
```yaml
title: Webshell Remote Command Execution
id: c0d3734d-330f-4a03-aae2-65dacc6a8222
status: experimental
description: Detects possible command execution by web application/web shell
author: Ilyas Ochkov, Beyu Denis, oscd.community
date: 2019/10/12
modified: 2021/11/11
references:
    - personal experience
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        syscall: 'execve'
        key: 'detect_execve_www'
    condition: selection
falsepositives:
    - Admin activity
    - Crazy web applications
level: critical
tags:
    - attack.persistence
    - attack.t1505.003
```
