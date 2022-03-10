---
title: "Using SettingSyncHost.exe as LOLBin"
aliases:
  - "/rule/b2ddd389-f676-4ac4-845a-e00781a48e5f"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1574.008



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects using SettingSyncHost.exe to run hijacked binary

<!--more-->


## Known false-positives

* unknown



## References

* https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_using_settingsynchost_as_lolbin.yml))
```yaml
title: Using SettingSyncHost.exe as LOLBin
id: b2ddd389-f676-4ac4-845a-e00781a48e5f
status: test
description: Detects using SettingSyncHost.exe to run hijacked binary
author: Anton Kutepov, oscd.community
references:
  - https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin
date: 2020/02/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  system_utility:
    Image|startswith:
      - 'C:\Windows\System32\'
      - 'C:\Windows\SysWOW64\'
  parent_is_settingsynchost:
    ParentCommandLine|contains|all:
      - 'cmd.exe /c'
      - 'RoamDiag.cmd'
      - '-outputpath'
  condition: not system_utility and parent_is_settingsynchost
fields:
  - TargetFilename
  - Image
falsepositives:
  - unknown
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1574.008

```