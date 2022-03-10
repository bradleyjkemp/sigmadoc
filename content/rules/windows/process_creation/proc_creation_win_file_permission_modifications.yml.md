---
title: "File or Folder Permissions Modifications"
aliases:
  - "/rule/37ae075c-271b-459b-8d7b-55ad5f993dd8"


tags:
  - attack.defense_evasion
  - attack.t1222.001



status: test





date: Wed, 23 Oct 2019 11:24:13 -0700


---

Detects a file or folder's permissions being modified.

<!--more-->


## Known false-positives

* Users interacting with the files on their own (unlikely unless privileged users).
* Dynatrace app



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_file_permission_modifications.yml))
```yaml
title: File or Folder Permissions Modifications
id: 37ae075c-271b-459b-8d7b-55ad5f993dd8
status: test
description: Detects a file or folder's permissions being modified.
author: Jakob Weinzettl, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md
date: 2019/10/23
modified: 2022/02/11
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\takeown.exe'
      - '\cacls.exe'
      - '\icacls.exe'
    CommandLine|contains: '/grant'
  selection2:
    Image|endswith: '\attrib.exe'
    CommandLine|contains: '-r'
  filter_reset:
    CommandLine|endswith: 'ICACLS C:\ProgramData\dynatrace\gateway\config\connectivity.history /reset'
  filter_grant:
    CommandLine|contains|all:
      - 'ICACLS C:\ProgramData\dynatrace\gateway\config\config.properties /grant :r '
      - 'S-1-5-19:F'
  condition: selection or selection2 and not 1 of filter*
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Users interacting with the files on their own (unlikely unless privileged users).
  - Dynatrace app
level: medium
tags:
  - attack.defense_evasion
  - attack.t1222.001

```
