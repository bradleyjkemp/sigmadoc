---
title: "System Shutdown/Reboot"
aliases:
  - "/rule/40b1fbe2-18ea-4ee7-be47-0294285811de"


tags:
  - attack.impact
  - attack.t1529



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* hhttps://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_system_shutdown_reboot.yml))
```yaml
title: 'System Shutdown/Reboot'
id: 40b1fbe2-18ea-4ee7-be47-0294285811de
status: test
description: 'Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.'
author: 'Igor Fits, Mikhail Larin, oscd.community'
references:
  - hhttps://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '/shutdown'
      - '/reboot'
      - '/halt'
  condition: selection
falsepositives:
  - 'Legitimate administrative activity'
level: informational
tags:
  - attack.impact
  - attack.t1529

```
