---
title: "Cisco Disabling Logging"
aliases:
  - "/rule/9e8f6035-88bf-4a63-96b6-b17c0508257e"
ruleid: 9e8f6035-88bf-4a63-96b6-b17c0508257e

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Turn off logging locally or remote

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_disable_logging.yml))
```yaml
title: Cisco Disabling Logging
id: 9e8f6035-88bf-4a63-96b6-b17c0508257e
status: test
description: Turn off logging locally or remote
author: Austin Clark
date: 2019/08/11
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'no logging'
    - 'no aaa new-model'
  condition: keywords
fields:
  - src
  - CmdSet
  - User
  - Privilege_Level
  - Remote_Address
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001

```
