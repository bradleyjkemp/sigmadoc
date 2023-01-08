---
title: "Code Injection by ld.so Preload"
aliases:
  - "/rule/7e3c4651-c347-40c4-b1d4-d48590fdf684"
ruleid: 7e3c4651-c347-40c4-b1d4-d48590fdf684

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1574.006



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the ld.so preload persistence file. See `man ld.so` for more information.

<!--more-->


## Known false-positives

* rare temporary workaround for library misconfiguration



## References

* https://man7.org/linux/man-pages/man8/ld.so.8.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_ldso_preload_injection.yml))
```yaml
title: Code Injection by ld.so Preload
id: 7e3c4651-c347-40c4-b1d4-d48590fdf684
status: experimental
description: Detects the ld.so preload persistence file. See `man ld.so` for more information.
author: Christian Burkard
date: 2021/05/05
references:
    - https://man7.org/linux/man-pages/man8/ld.so.8.html
logsource:
    product: linux
detection:
    keyword: 
        - '/etc/ld.so.preload'
    condition: keyword
falsepositives:
    - rare temporary workaround for library misconfiguration
level: high
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1574.006
```
