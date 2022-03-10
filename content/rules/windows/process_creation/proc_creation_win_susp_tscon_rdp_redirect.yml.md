---
title: "Suspicious RDP Redirect Using TSCON"
aliases:
  - "/rule/f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb"


tags:
  - attack.lateral_movement
  - attack.t1563.002
  - attack.t1021.001
  - car.2013-07-002



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious RDP session redirect using tscon.exe

<!--more-->


## Known false-positives

* Unknown



## References

* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_tscon_rdp_redirect.yml))
```yaml
title: Suspicious RDP Redirect Using TSCON
id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: test
description: Detects a suspicious RDP session redirect using tscon.exe
author: Florian Roth
references:
  - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
  - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
date: 2018/03/17
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: ' /dest:rdp-tcp:'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.lateral_movement
  - attack.t1563.002
  - attack.t1021.001
  - car.2013-07-002

```
