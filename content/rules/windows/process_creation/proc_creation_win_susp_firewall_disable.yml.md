---
title: "Firewall Disabled via Netsh"
aliases:
  - "/rule/57c4bf16-227f-4394-8ec7-1b745ee061c3"
ruleid: 57c4bf16-227f-4394-8ec7-1b745ee061c3

tags:
  - attack.defense_evasion
  - attack.t1562.004
  - attack.s0108



status: test





date: Mon, 4 Nov 2019 16:10:10 +0100


---

Detects netsh commands that turns off the Windows firewall

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://www.winhelponline.com/blog/enable-and-disable-windows-firewall-quickly-using-command-line/
* https://app.any.run/tasks/210244b9-0b6b-4a2c-83a3-04bd3175d017/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md#atomic-test-1---disable-microsoft-defender-firewall


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_firewall_disable.yml))
```yaml
title: Firewall Disabled via Netsh
id: 57c4bf16-227f-4394-8ec7-1b745ee061c3
status: test
description: Detects netsh commands that turns off the Windows firewall
author: Fatih Sirin
references:
  - https://www.winhelponline.com/blog/enable-and-disable-windows-firewall-quickly-using-command-line/
  - https://app.any.run/tasks/210244b9-0b6b-4a2c-83a3-04bd3175d017/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md#atomic-test-1---disable-microsoft-defender-firewall
date: 2019/11/01
modified: 2022/01/09
logsource:
  category: process_creation
  product: windows
detection:
  selection_1:
    CommandLine|contains|all:
      - netsh
      - firewall
      - set
      - opmode
      - 'mode=disable'
  selection_2:
    CommandLine|contains|all:    
      - netsh
      - advfirewall
      - set
      - state
      - 'off'
  condition: 1 of selection_*
falsepositives:
  - Legitimate administration
level: medium
tags:
  - attack.defense_evasion
  - attack.t1562.004
  - attack.s0108

```