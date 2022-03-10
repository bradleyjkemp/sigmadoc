---
title: "Screen Capture - macOS"
aliases:
  - "/rule/0877ed01-da46-4c49-8476-d49cdd80dfa7"


tags:
  - attack.collection
  - attack.t1113



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects attempts to use screencapture to collect macOS screenshots

<!--more-->


## Known false-positives

* Legitimate user activity taking screenshots



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md
* https://github.com/BC-SECURITY/Empire/blob/master/lib/modules/python/collection/osx/screenshot.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_screencapture.yml))
```yaml
title: Screen Capture - macOS
id: 0877ed01-da46-4c49-8476-d49cdd80dfa7
status: test
description: Detects attempts to use screencapture to collect macOS screenshots
author: remotephone, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md
  - https://github.com/BC-SECURITY/Empire/blob/master/lib/modules/python/collection/osx/screenshot.py
date: 2020/10/13
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection:
    Image: '/usr/sbin/screencapture'
  condition: selection
falsepositives:
  - Legitimate user activity taking screenshots
level: low
tags:
  - attack.collection
  - attack.t1113

```
