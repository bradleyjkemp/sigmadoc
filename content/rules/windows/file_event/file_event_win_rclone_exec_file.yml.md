---
title: "Rclone Config File Creation"
aliases:
  - "/rule/34986307-b7f4-49be-92f3-e7a4d01ac5db"
ruleid: 34986307-b7f4-49be-92f3-e7a4d01ac5db

tags:
  - attack.exfiltration
  - attack.t1567.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Rclone config file being created

<!--more-->


## Known false-positives

* Legitimate Rclone usage (rare)



## References

* https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_rclone_exec_file.yml))
```yaml
title: Rclone Config File Creation
id: 34986307-b7f4-49be-92f3-e7a4d01ac5db
description: Detects Rclone config file being created
status: experimental
date: 2021/05/26
modified: 2021/10/04
author: Aaron Greetham (@beardofbinary) - NCC Group
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
tags:
    - attack.exfiltration
    - attack.t1567.002
falsepositives:
    - Legitimate Rclone usage (rare)
level: high 
logsource:
    product: windows
    category: file_event
detection:
    file_selection:
        TargetFilename|contains|all:
            - ':\Users\'
            - '\.config\rclone\'
    condition: file_selection
```
