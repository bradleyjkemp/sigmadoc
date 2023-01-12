---
title: "Mounted Windows Admin Shares with net.exe"
aliases:
  - "/rule/3abd6094-7027-475f-9630-8ab9be7b9725"
ruleid: 3abd6094-7027-475f-9630-8ab9be7b9725

tags:
  - attack.lateral_movement
  - attack.t1021.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects when an admin share is mounted using net.exe

<!--more-->


## Known false-positives

* Administrators



## References

* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_net_use_admin_share.yml))
```yaml
title: Mounted Windows Admin Shares with net.exe
id: 3abd6094-7027-475f-9630-8ab9be7b9725
status: experimental
description: Detects when an admin share is mounted using net.exe
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: 'oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga'
date: 2020/10/05
modified: 2021/06/27
tags:
    - attack.lateral_movement
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains|all:
            - ' use '
            - '\\\*\\*$' # (Specs) If some wildcard after a backslash should be searched, the backslash has to be escaped: \\*
    condition: selection
falsepositives:
    - Administrators
level: medium

```