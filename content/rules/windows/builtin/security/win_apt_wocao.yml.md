---
title: "Operation Wocao Activity"
aliases:
  - "/rule/74ad4314-482e-4c3e-b237-3f7ed3b9ca8d"


tags:
  - attack.discovery
  - attack.t1012
  - attack.defense_evasion
  - attack.t1036.004
  - attack.t1027
  - attack.execution
  - attack.t1053.005
  - attack.t1059.001



status: experimental





date: Fri, 20 Dec 2019 15:00:07 +0100


---

Detects activity mentioned in Operation Wocao report

<!--more-->


## Known false-positives

* Administrators that use checkadmin.exe tool to enumerate local administrators



## References

* https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/
* https://twitter.com/SBousseaden/status/1207671369963646976


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_apt_wocao.yml))
```yaml
title: Operation Wocao Activity
id: 74ad4314-482e-4c3e-b237-3f7ed3b9ca8d
author: Florian Roth, frack113
status: experimental
description: Detects activity mentioned in Operation Wocao report
references:
    - https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/
    - https://twitter.com/SBousseaden/status/1207671369963646976
tags:
    - attack.discovery 
    - attack.t1012
    - attack.defense_evasion
    - attack.t1036.004
    - attack.t1027
    - attack.execution
    - attack.t1053.005
    - attack.t1059.001
date: 2019/12/20
modified: 2021/09/19
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4799
        TargetUserName|startswith: 'Administr'
        CallerProcessName|endswith: '\checkadmin.exe'
    condition: selection
falsepositives:
    - Administrators that use checkadmin.exe tool to enumerate local administrators
level: high
```
