---
title: "Gatekeeper Bypass via Xattr"
aliases:
  - "/rule/f5141b6d-9f42-41c6-a7bf-2a780678b29b"
ruleid: f5141b6d-9f42-41c6-a7bf-2a780678b29b

tags:
  - attack.defense_evasion
  - attack.t1553.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects macOS Gatekeeper bypass via xattr utility

<!--more-->


## Known false-positives

* Legitimate activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.001/T1553.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_xattr_gatekeeper_bypass.yml))
```yaml
title: Gatekeeper Bypass via Xattr
id: f5141b6d-9f42-41c6-a7bf-2a780678b29b
status: test
description: Detects macOS Gatekeeper bypass via xattr utility
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.001/T1553.001.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image|endswith: '/xattr'
    CommandLine|contains|all:
      - '-r'
      - 'com.apple.quarantine'
  condition: selection
falsepositives:
  - Legitimate activities
level: low
tags:
  - attack.defense_evasion
  - attack.t1553.001

```