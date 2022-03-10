---
title: "Suspicious Add User to Remote Desktop Users Group"
aliases:
  - "/rule/ffa28e60-bdb1-46e0-9f82-05f7a61cc06e"


tags:
  - attack.persistence
  - attack.t1133
  - attack.t1136.001
  - attack.lateral_movement
  - attack.t1021.001



status: experimental





date: Mon, 6 Dec 2021 18:29:50 +0100


---

Detects suspicious command line in which a user gets added to the local Remote Desktop Users group

<!--more-->


## Known false-positives

* Administrative activity



## References

* https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_add_user_remote_desktop.yml))
```yaml
title: Suspicious Add User to Remote Desktop Users Group
id: ffa28e60-bdb1-46e0-9f82-05f7a61cc06e
status: experimental
description: Detects suspicious command line in which a user gets added to the local Remote Desktop Users group
author: Florian Roth
date: 2021/12/06
references:
    - https://www.microsoft.com/security/blog/2021/11/16/evolving-trends-in-iranian-threat-actor-activity-mstic-presentation-at-cyberwarcon-2021/
tags:
    - attack.persistence
    - attack.t1133
    - attack.t1136.001
    - attack.lateral_movement
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'net '
            - 'localgroup'
            - 'Remote Desktop Users'
            - '/add'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: high

```
