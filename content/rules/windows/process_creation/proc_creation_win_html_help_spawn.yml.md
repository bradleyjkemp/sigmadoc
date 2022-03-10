---
title: "HTML Help Shell Spawn"
aliases:
  - "/rule/52cad028-0ff0-4854-8f67-d25dfcbc78b4"


tags:
  - attack.defense_evasion
  - attack.t1218.001
  - attack.t1218.010
  - attack.t1218.011
  - attack.execution
  - attack.t1059.001
  - attack.t1059.003
  - attack.t1059.005
  - attack.t1059.007
  - attack.t1047



status: test





date: Fri, 3 Apr 2020 16:56:26 +0300


---

Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)

<!--more-->


## Known false-positives

* unknown



## References

* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_html_help_spawn.yml))
```yaml
title: HTML Help Shell Spawn
id: 52cad028-0ff0-4854-8f67-d25dfcbc78b4
status: test
description: Detects a suspicious child process of a Microsoft HTML Help system when executing compiled HTML files (.chm)
author: Maxim Pavlunin
references:
  - https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan/
date: 2020/04/01
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage: 'C:\Windows\hh.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\regsvr32.exe'
      - '\wmic.exe'
      - '\rundll32.exe'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.001
  - attack.t1218.010
  - attack.t1218.011
  - attack.execution
  - attack.t1059.001
  - attack.t1059.003
  - attack.t1059.005
  - attack.t1059.007
  - attack.t1047

```
