---
title: "Use of CLIP"
aliases:
  - "/rule/ddeff553-5233-4ae9-bbab-d64d2bd634be"
ruleid: ddeff553-5233-4ae9-bbab-d64d2bd634be

tags:
  - attack.collection
  - attack.t1115



status: experimental





date: Tue, 27 Jul 2021 08:50:03 +0200


---

Adversaries may collect data stored in the clipboard from users copying information within or between applications.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/clip
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_clip.yml))
```yaml
title: Use of CLIP
id: ddeff553-5233-4ae9-bbab-d64d2bd634be
status: experimental
author: frack113
date: 2021/07/27
description: Adversaries may collect data stored in the clipboard from users copying information within or between applications. 
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/clip
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1115/T1115.md
tags:
    - attack.collection
    - attack.t1115
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: clip.exe
    condition: selection 
falsepositives:
    - Unknown
level: low

```
