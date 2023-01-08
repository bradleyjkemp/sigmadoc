---
title: "Disabled Volume Snapshots"
aliases:
  - "/rule/dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a"
ruleid: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects commands that temporarily turn off Volume Snapshots

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://twitter.com/0gtweet/status/1354766164166115331


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_volsnap_disable.yml))
```yaml
title: Disabled Volume Snapshots
id: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
description: Detects commands that temporarily turn off Volume Snapshots
references:
    - https://twitter.com/0gtweet/status/1354766164166115331
date: 2021/01/28
status: experimental
author: Florian Roth
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'reg'
            - ' add '
            - '\Services\VSS\Diag' 
            - '/d Disabled'
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```
