---
title: "OpenWith.exe Executes Specified Binary"
aliases:
  - "/rule/cec8e918-30f7-4e2d-9bfa-a59cc97ae60f"
ruleid: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f

tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Wed, 23 Oct 2019 13:00:21 +0200


---

The OpenWith.exe executes other binary

<!--more-->


## Known false-positives

* Legitimate use of OpenWith.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
* https://twitter.com/harr0ey/status/991670870384021504


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_openwith.yml))
```yaml
title: OpenWith.exe Executes Specified Binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: test
description: The OpenWith.exe executes other binary
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
  - https://twitter.com/harr0ey/status/991670870384021504
date: 2019/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\OpenWith.exe'
    CommandLine|contains: '/c'
  condition: selection
falsepositives:
  - Legitimate use of OpenWith.exe by legitimate user
level: high
tags:
  - attack.defense_evasion
  - attack.t1218

```
