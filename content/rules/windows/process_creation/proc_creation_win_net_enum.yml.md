---
title: "Windows Network Enumeration"
aliases:
  - "/rule/62510e69-616b-4078-b371-847da438cc03"


tags:
  - attack.discovery
  - attack.t1018



status: stable





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.

<!--more-->


## Known false-positives

* Legitimate use of net.exe utility by legitimate user



## References

* https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_net_enum.yml))
```yaml
title: Windows Network Enumeration
id: 62510e69-616b-4078-b371-847da438cc03
status: stable
description: Identifies attempts to enumerate hosts in a network using the built-in Windows net.exe tool.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md
author: Endgame, JHasenbusch (ported for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'view'
    filter:
        CommandLine|contains: \\\
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legitimate use of net.exe utility by legitimate user
level: low 

```