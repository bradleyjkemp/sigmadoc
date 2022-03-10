---
title: "Cisco Local Accounts"
aliases:
  - "/rule/6d844f0f-1c18-41af-8f19-33e7654edfc3"


tags:
  - attack.persistence
  - attack.t1136.001
  - attack.t1098



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Find local accounts being created or modified as well as remote authentication configurations

<!--more-->


## Known false-positives

* When remote authentication is in place, this should not change often




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_local_accounts.yml))
```yaml
title: Cisco Local Accounts
id: 6d844f0f-1c18-41af-8f19-33e7654edfc3
status: test
description: Find local accounts being created or modified as well as remote authentication configurations
author: Austin Clark
date: 2019/08/12
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'username'
    - 'aaa'
  condition: keywords
fields:
  - CmdSet
falsepositives:
  - When remote authentication is in place, this should not change often
level: high
tags:
  - attack.persistence
  - attack.t1136.001
  - attack.t1098

```
