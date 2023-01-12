---
title: "Path To Screensaver Binary Modified"
aliases:
  - "/rule/67a6c006-3fbe-46a7-9074-2ba3b82c3000"
ruleid: 67a6c006-3fbe-46a7-9074-2ba3b82c3000

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects value modification of registry key containing path to binary used as screensaver.

<!--more-->


## Known false-positives

* Legitimate modification of screensaver.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md
* https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_modify_screensaver_binary_path.yml))
```yaml
title: Path To Screensaver Binary Modified
id: 67a6c006-3fbe-46a7-9074-2ba3b82c3000
status: test
description: Detects value modification of registry key containing path to binary used as screensaver.
author: Bartlomiej Czyz @bczyz1, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md
  - https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf
date: 2020/10/11
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|endswith: '\Control Panel\Desktop\SCRNSAVE.EXE' # HKEY_CURRENT_USER\Control Panel\Desktop\SCRNSAVE.EXE
  filter:
    Image|endswith:
      - '\rundll32.exe'
      - '\explorer.exe'
  condition: selection and not filter
falsepositives:
  - 'Legitimate modification of screensaver.'
level: medium
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.002

```