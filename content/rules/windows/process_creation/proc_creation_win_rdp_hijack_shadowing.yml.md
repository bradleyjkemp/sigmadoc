---
title: "MSTSC Shadowing"
aliases:
  - "/rule/6ba5a05f-b095-4f0a-8654-b825f4f16334"


tags:
  - attack.lateral_movement
  - attack.t1563.002



status: test





date: Fri, 24 Jan 2020 16:18:19 +0100


---

Detects RDP session hijacking by using MSTSC shadowing

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/kmkz_security/status/1220694202301976576
* https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_rdp_hijack_shadowing.yml))
```yaml
title: MSTSC Shadowing
id: 6ba5a05f-b095-4f0a-8654-b825f4f16334
status: test
description: Detects RDP session hijacking by using MSTSC shadowing
author: Florian Roth
references:
  - https://twitter.com/kmkz_security/status/1220694202301976576
  - https://github.com/kmkz/Pentesting/blob/master/Post-Exploitation-Cheat-Sheet
date: 2020/01/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'noconsentprompt'
      - 'shadow:'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.lateral_movement
  - attack.t1563.002

```
