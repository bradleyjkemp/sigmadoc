---
title: "File Deletion"
aliases:
  - "/rule/30aed7b6-d2c1-4eaf-9382-b6bc43e50c57"
ruleid: 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57

tags:
  - attack.defense_evasion
  - attack.t1070.004



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects file deletion commands

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_file_deletion.yml))
```yaml
title: File Deletion
id: 30aed7b6-d2c1-4eaf-9382-b6bc43e50c57
status: stable
description: Detects file deletion commands
author: Ömer Günal, oscd.community
date: 2020/10/07
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.004/T1070.004.md
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/rm'     # covers /rmdir as well
            - '/shred'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
tags:
    - attack.defense_evasion
    - attack.t1070.004

```
