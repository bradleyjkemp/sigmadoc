---
title: "SQL Client Tools PowerShell Session Detection"
aliases:
  - "/rule/a746c9b8-a2fb-4ee5-a428-92bee9e99060"
ruleid: a746c9b8-a2fb-4ee5-a428-92bee9e99060

tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1127



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio. Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.

<!--more-->


## Known false-positives

* Direct PS command execution through SQLToolsPS.exe is uncommon, childprocess sqltoolsps.exe spawned by smss.exe is a legitimate action.



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Sqltoolsps.yml
* https://twitter.com/pabraeken/status/993298228840992768


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_use_of_sqltoolsps_bin.yml))
```yaml
title: SQL Client Tools PowerShell Session Detection
id: a746c9b8-a2fb-4ee5-a428-92bee9e99060
status: test
description: This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio. Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs.
author: 'Agro (@agro_sev) oscd.communitly'
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Sqltoolsps.yml
  - https://twitter.com/pabraeken/status/993298228840992768
date: 2020/10/13
modified: 2022/02/25
logsource:
  category: process_creation
  product: windows
detection:
  selection_1:
    Image|endswith: '\sqltoolsps.exe'
  selection_2:
    ParentImage|endswith: '\sqltoolsps.exe'
  selection_3:
    OriginalFileName: '\sqltoolsps.exe'
  filter:
    ParentImage|endswith: '\smss.exe'
  condition: 1 of selection_* and not filter
falsepositives:
  - Direct PS command execution through SQLToolsPS.exe is uncommon, childprocess sqltoolsps.exe spawned by smss.exe is a legitimate action.
level: medium
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1127

```
