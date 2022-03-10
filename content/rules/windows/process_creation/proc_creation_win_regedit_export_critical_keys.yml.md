---
title: "Exports Critical Registry Keys To a File"
aliases:
  - "/rule/82880171-b475-4201-b811-e9c826cd5eaa"


tags:
  - attack.exfiltration
  - attack.t1012



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the export of a crital Registry key to a file.

<!--more-->


## Known false-positives

* Dumping hives for legitimate purpouse i.e. backup or forensic investigation



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regedit_export_critical_keys.yml))
```yaml
title: Exports Critical Registry Keys To a File
id: 82880171-b475-4201-b811-e9c826cd5eaa
status: test
description: Detects the export of a crital Registry key to a file.
author: Oddvar Moe, Sander Wiebing, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
date: 2020/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regedit.exe'
    CommandLine|contains: ' /E '
  selection_2:
    CommandLine|contains:
      - 'hklm'
      - 'hkey_local_machine'
  selection_3:
    CommandLine|endswith:
      - '\system'
      - '\sam'
      - '\security'
  condition: selection and selection_2 and selection_3
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Dumping hives for legitimate purpouse i.e. backup or forensic investigation
level: high
tags:
  - attack.exfiltration
  - attack.t1012

```
