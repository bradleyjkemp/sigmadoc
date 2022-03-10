---
title: "Exports Registry Key To a File"
aliases:
  - "/rule/f0e53e89-8d22-46ea-9db5-9d4796ee2f8a"


tags:
  - attack.exfiltration
  - attack.t1012



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the export of the target Registry key to a file.

<!--more-->


## Known false-positives

* Legitimate export of keys



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regedit_export_keys.yml))
```yaml
title: Exports Registry Key To a File
id: f0e53e89-8d22-46ea-9db5-9d4796ee2f8a
status: test
description: Detects the export of the target Registry key to a file.
author: Oddvar Moe, Sander Wiebing, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regedit.exe'
    CommandLine|contains: ' /E '
  filter_1:   # filters to avoid intersection with critical keys rule
    CommandLine|contains:
      - 'hklm'
      - 'hkey_local_machine'
  filter_2:
    CommandLine|endswith:
      - '\system'
      - '\sam'
      - '\security'
  condition: selection and not (filter_1 and filter_2)
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Legitimate export of keys
level: low
tags:
  - attack.exfiltration
  - attack.t1012

```
