---
title: "Possible Coin Miner CPU Priority Param"
aliases:
  - "/rule/071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed"


tags:
  - attack.privilege_escalation
  - attack.t1068



status: experimental





date: Sat, 9 Oct 2021 10:28:16 +0200


---

Detects command line parameter very often used with coin miners

<!--more-->


## Known false-positives

* Other tools that use a --cpu-priority flag



## References

* https://xmrig.com/docs/miner/command-line-options


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_coinminer.yml))
```yaml
title: Possible Coin Miner CPU Priority Param
id: 071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed
status: experimental
description: Detects command line parameter very often used with coin miners
author: Florian Roth
date: 2021/10/09
references:
    - https://xmrig.com/docs/miner/command-line-options
tags:
    - attack.privilege_escalation
    - attack.t1068
logsource:
    product: linux
    service: auditd
detection:
    cmd1:
        a1|startswith: '--cpu-priority'
    cmd2:
        a2|startswith: '--cpu-priority'
    cmd3:
        a3|startswith: '--cpu-priority'
    cmd4:
        a4|startswith: '--cpu-priority'
    cmd5:
        a5|startswith: '--cpu-priority'
    cmd6:
        a6|startswith: '--cpu-priority'
    cmd7:
        a7|startswith: '--cpu-priority'
    condition: 1 of cmd*
falsepositives:
    - Other tools that use a --cpu-priority flag
level: critical
```
