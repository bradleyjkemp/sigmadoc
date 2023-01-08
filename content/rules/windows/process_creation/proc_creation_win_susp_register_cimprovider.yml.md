---
title: "DLL Execution Via Register-cimprovider.exe"
aliases:
  - "/rule/a2910908-e86f-4687-aeba-76a5f996e652"
ruleid: a2910908-e86f-4687-aeba-76a5f996e652

tags:
  - attack.defense_evasion
  - attack.t1574



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects using register-cimprovider.exe to execute arbitrary dll file.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/PhilipTsukerman/status/992021361106268161
* https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Register-cimprovider.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_register_cimprovider.yml))
```yaml
title: DLL Execution Via Register-cimprovider.exe
id: a2910908-e86f-4687-aeba-76a5f996e652
status: test
description: Detects using register-cimprovider.exe to execute arbitrary dll file.
author: Ivan Dyachkov, Yulia Fomina, oscd.community
references:
  - https://twitter.com/PhilipTsukerman/status/992021361106268161
  - https://github.com/api0cradle/LOLBAS/blob/master/OSBinaries/Register-cimprovider.md
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
  definition: 'Requirements: Sysmon ProcessCreation logging must be activated and Windows audit msut Include command line in process creation events'
detection:
  selection:
    Image|endswith: '\register-cimprovider.exe'
    CommandLine|contains|all:
      - '-path'
      - 'dll'
  condition: selection
fields:
  - CommandLine
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1574

```
