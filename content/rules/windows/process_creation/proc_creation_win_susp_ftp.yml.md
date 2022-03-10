---
title: "Suspicious ftp.exe"
aliases:
  - "/rule/06b401f4-107c-4ff9-947f-9ec1e7649f1e"


tags:
  - attack.execution
  - attack.t1059
  - attack.defense_evasion
  - attack.t1202



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects renamed ftp.exe, ftp.exe script execution and child processes ran by ftp.exe

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Ftp.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ftp.yml))
```yaml
title: Suspicious ftp.exe
id: 06b401f4-107c-4ff9-947f-9ec1e7649f1e
status: test
description: Detects renamed ftp.exe, ftp.exe script execution and child processes ran by ftp.exe
author: Victor Sergeev, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Ftp.yml
date: 2020/10/09
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  ftp_path:
    Image|endswith: 'ftp.exe'
  ftp_metadata:
    OriginalFileName|contains: 'ftp.exe'
  cmd_with_script_modifier:
    CommandLine|contains: '-s:'
  parent_path:
    ParentImage|endswith: 'ftp.exe'
  condition: (ftp_path and cmd_with_script_modifier) or (ftp_metadata and cmd_with_script_modifier) or (ftp_metadata and not ftp_path) or parent_path
fields:
  - CommandLine
  - ParentImage
falsepositives:
  - Unknown
level: medium
tags:
  - attack.execution
  - attack.t1059
  - attack.defense_evasion
  - attack.t1202

```