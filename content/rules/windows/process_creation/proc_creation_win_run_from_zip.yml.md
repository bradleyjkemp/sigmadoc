---
title: "Run from a Zip File"
aliases:
  - "/rule/1a70042a-6622-4a2b-8958-267625349abf"


tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Sat, 15 Jan 2022 17:04:03 +0100


---

Payloads may be compressed, archived, or encrypted in order to avoid detection

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-4---execution-from-compressed-file


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_run_from_zip.yml))
```yaml
title: Run from a Zip File
id: 1a70042a-6622-4a2b-8958-267625349abf
status: experimental
description: Payloads may be compressed, archived, or encrypted in order to avoid detection
author: frack113
date: 2021/12/26
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-4---execution-from-compressed-file
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: '.zip\'
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
    - attack.impact
    - attack.t1485
```
