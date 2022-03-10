---
title: "Rubeus Hack Tool"
aliases:
  - "/rule/7ec2c172-dceb-4c10-92c9-87c1881b7e18"


tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1558.003
  - attack.lateral_movement
  - attack.t1550.003



status: stable





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects command line parameters used by Rubeus hack tool

<!--more-->


## Known false-positives

* unlikely



## References

* https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_rubeus.yml))
```yaml
title: Rubeus Hack Tool
id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
status: stable
description: Detects command line parameters used by Rubeus hack tool
author: Florian Roth
references:
  - https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/
date: 2018/12/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ' asreproast '
      - ' dump /service:krbtgt '
      - ' kerberoast '
      - ' createnetonly /program:'
      - ' ptt /ticket:'
      - ' /impersonateuser:'
      - ' renew /ticket:'
      - ' asktgt /user:'
      - ' harvest /interval:'
      - ' s4u /user:'
      - ' s4u /ticket:'
      - ' hash /password:'
  condition: selection
falsepositives:
  - unlikely
level: critical
tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1558.003
  - attack.lateral_movement
  - attack.t1550.003

```