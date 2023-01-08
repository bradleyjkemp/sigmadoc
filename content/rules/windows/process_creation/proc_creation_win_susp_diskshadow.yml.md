---
title: "Execution via Diskshadow.exe"
aliases:
  - "/rule/0c2f8629-7129-4a8a-9897-7e0768f13ff2"
ruleid: 0c2f8629-7129-4a8a-9897-7e0768f13ff2

tags:
  - attack.execution
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects using Diskshadow.exe to execute arbitrary code in text file

<!--more-->


## Known false-positives

* False postitve can be if administrators use diskshadow tool in their infrastructure as a main backup tool with scripts.



## References

* https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_diskshadow.yml))
```yaml
title: Execution via Diskshadow.exe
id: 0c2f8629-7129-4a8a-9897-7e0768f13ff2
status: test
description: Detects using Diskshadow.exe to execute arbitrary code in text file
author: Ivan Dyachkov, oscd.community
references:
  - https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
  definition: 'Requirements: Sysmon ProcessCreation logging must be activated and Windows audit must Include command line in process creation events'
detection:
  selection:
    Image|endswith: '\diskshadow.exe'
    CommandLine|contains:
      - '/s'
      - '-s'
  condition: selection
fields:
  - CommandLine
falsepositives:
  - False postitve can be if administrators use diskshadow tool in their infrastructure as a main backup tool with scripts.
level: high
tags:
  - attack.execution
  - attack.t1218

```
