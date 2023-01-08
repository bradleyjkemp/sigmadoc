---
title: "Suspicious Get Local Groups Information with WMIC"
aliases:
  - "/rule/164eda96-11b2-430b-85ff-6a265c15bf32"
ruleid: 164eda96-11b2-430b-85ff-6a265c15bf32

tags:
  - attack.discovery
  - attack.t1069.001



status: experimental





date: Sun, 12 Dec 2021 12:15:27 +0100


---

Adversaries may attempt to find local system groups and permission settings.
The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.
Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_suspicious_ad_reco.yml))
```yaml
title: Suspicious Get Local Groups Information with WMIC
id: 164eda96-11b2-430b-85ff-6a265c15bf32
status: experimental
description: |
    Adversaries may attempt to find local system groups and permission settings.
    The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group.
    Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md
author: frack113
date: 2021/12/12
logsource:
    product: windows
    category: process_creation
detection:
    test_5:
        Image|endswith: '\wmic.exe'
        CommandLine|contains: ' group'
    condition: test_5
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1069.001
```
