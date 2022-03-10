---
title: "Startup Items"
aliases:
  - "/rule/dfe8b941-4e54-4242-b674-6b613d521962"


tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1037.005



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.005/T1037.005.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/file_event/file_event_macos_startup_items.yml))
```yaml
title: Startup Items
id: dfe8b941-4e54-4242-b674-6b613d521962
status: test
description: Detects creation of startup item plist files that automatically get executed at boot initialization to establish persistence.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1037.005/T1037.005.md
date: 2020/10/14
modified: 2021/11/27
logsource:
  category: file_event
  product: macos
detection:
  selection_1:
    TargetFilename|contains: '/Library/StartupItems/'
  selection_2:
    TargetFilename|endswith: '.plist'
  condition: selection_1 and selection_2
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1037.005

```
