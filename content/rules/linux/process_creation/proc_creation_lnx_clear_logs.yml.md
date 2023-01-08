---
title: "Clear Linux Logs"
aliases:
  - "/rule/80915f59-9b56-4616-9de0-fd0dea6c12fe"
ruleid: 80915f59-9b56-4616-9de0-fd0dea6c12fe

tags:
  - attack.defense_evasion
  - attack.t1070.002



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects clear logs

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_clear_logs.yml))
```yaml
title: Clear Linux Logs
id: 80915f59-9b56-4616-9de0-fd0dea6c12fe
status: stable
description: Detects clear logs
author: Ömer Günal, oscd.community
date: 2020/10/07
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/rm'    # covers /rmdir as well
            - '/shred'
        CommandLine|contains:
            - '/var/log'
            - '/var/spool/mail'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: medium
tags:
    - attack.defense_evasion
    - attack.t1070.002

```
