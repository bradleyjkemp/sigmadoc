---
title: "Cisco Clear Logs"
aliases:
  - "/rule/ceb407f6-8277-439b-951f-e4210e3ed956"


tags:
  - attack.defense_evasion
  - attack.t1070.003



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Clear command history in network OS which is used for defense evasion

<!--more-->


## Known false-positives

* Legitimate administrators may run these commands




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_clear_logs.yml))
```yaml
title: Cisco Clear Logs
id: ceb407f6-8277-439b-951f-e4210e3ed956
status: test
description: Clear command history in network OS which is used for defense evasion
author: Austin Clark
date: 2019/08/12
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'clear logging'
    - 'clear archive'
  condition: keywords
fields:
  - src
  - CmdSet
  - User
  - Privilege_Level
  - Remote_Address
falsepositives:
  - Legitimate administrators may run these commands
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.003

```
