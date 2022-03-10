---
title: "Suspicious Where Execution"
aliases:
  - "/rule/725a9768-0f5e-4cb3-aec2-bc5719c6831a"


tags:
  - attack.discovery
  - attack.t1217



status: experimental





date: Mon, 13 Dec 2021 11:02:33 +0100


---

Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_where_execution.yml))
```yaml
title: Suspicious Where Execution
id: 725a9768-0f5e-4cb3-aec2-bc5719c6831a
status: experimental
description: |
    Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
    Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
    internal network resources such as servers, tools/dashboards, or other related infrastructure.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md
author: frack113
date: 2021/12/13
logsource:
    category: process_creation
    product: windows
detection:
    where_exe:
        Image|endswith: '\where.exe'
    where_opt:
        CommandLine|contains:
            - 'Bookmarks'
            - 'places.sqlite'
    condition: all of where_*
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1217
```
