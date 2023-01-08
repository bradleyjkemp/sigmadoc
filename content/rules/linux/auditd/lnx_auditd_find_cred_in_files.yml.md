---
title: "Credentials In Files"
aliases:
  - "/rule/df3fcaea-2715-4214-99c5-0056ea59eb35"
ruleid: df3fcaea-2715-4214-99c5-0056ea59eb35

tags:
  - attack.credential_access
  - attack.t1552.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detecting attempts to extract passwords with grep

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_find_cred_in_files.yml))
```yaml
title: 'Credentials In Files'
id: df3fcaea-2715-4214-99c5-0056ea59eb35
status: test
description: 'Detecting attempts to extract passwords with grep'
author: 'Igor Fits, oscd.community'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1552.001/T1552.001.md
date: 2020/10/15
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  execve:
    type: 'EXECVE'
  passwordgrep:
    - 'grep'
    - 'password'
  condition: execve and all of passwordgrep
falsepositives:
  - 'Unknown'
level: high
tags:
  - attack.credential_access
  - attack.t1552.001

```
