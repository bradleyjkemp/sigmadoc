---
title: "Cisco Denial of Service"
aliases:
  - "/rule/d94a35f0-7a29-45f6-90a0-80df6159967c"


tags:
  - attack.impact
  - attack.t1495
  - attack.t1529
  - attack.t1565.001



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Detect a system being shutdown or put into different boot mode

<!--more-->


## Known false-positives

* Legitimate administrators may run these commands, though rarely.




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_dos.yml))
```yaml
title: Cisco Denial of Service
id: d94a35f0-7a29-45f6-90a0-80df6159967c
status: test
description: Detect a system being shutdown or put into different boot mode
author: Austin Clark
date: 2019/08/15
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'shutdown'
    - 'config-register 0x2100'
    - 'config-register 0x2142'
  condition: keywords
fields:
  - CmdSet
falsepositives:
  - Legitimate administrators may run these commands, though rarely.
level: medium
tags:
  - attack.impact
  - attack.t1495
  - attack.t1529
  - attack.t1565.001

```
