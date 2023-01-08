---
title: "Cisco Collect Data"
aliases:
  - "/rule/cd072b25-a418-4f98-8ebc-5093fb38fe1a"
ruleid: cd072b25-a418-4f98-8ebc-5093fb38fe1a

tags:
  - attack.discovery
  - attack.credential_access
  - attack.collection
  - attack.t1087.001
  - attack.t1552.001
  - attack.t1005



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Collect pertinent data from the configuration files

<!--more-->


## Known false-positives

* Commonly run by administrators




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_collect_data.yml))
```yaml
title: Cisco Collect Data
id: cd072b25-a418-4f98-8ebc-5093fb38fe1a
status: test
description: Collect pertinent data from the configuration files
author: Austin Clark
date: 2019/08/11
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'show running-config'
    - 'show startup-config'
    - 'show archive config'
    - 'more'
  condition: keywords
fields:
  - src
  - CmdSet
  - User
  - Privilege_Level
  - Remote_Address
falsepositives:
  - Commonly run by administrators
level: low
tags:
  - attack.discovery
  - attack.credential_access
  - attack.collection
  - attack.t1087.001
  - attack.t1552.001
  - attack.t1005

```
