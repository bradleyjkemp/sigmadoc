---
title: "Imports Registry Key From a File"
aliases:
  - "/rule/73bba97f-a82d-42ce-b315-9182e76c57b1"
ruleid: 73bba97f-a82d-42ce-b315-9182e76c57b1

tags:
  - attack.t1112
  - attack.defense_evasion



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the import of the specified file to the registry with regedit.exe.

<!--more-->


## Known false-positives

* Legitimate import of keys
* Evernote



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regedit_import_keys.yml))
```yaml
title: Imports Registry Key From a File
id: 73bba97f-a82d-42ce-b315-9182e76c57b1
status: test
description: Detects the import of the specified file to the registry with regedit.exe.
author: Oddvar Moe, Sander Wiebing, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
date: 2020/10/07
modified: 2022/02/15
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regedit.exe'
    CommandLine|contains:
      - ' /i '
      - ' /s '
      - '.reg'
  filter:
    CommandLine|contains:
      - ' /e '
      - ' /a '
      - ' /c '
  filter_2:
    CommandLine|re: ':[^ \\\\]'     # to avoid intersection with ADS rule
  condition: selection and not filter and not filter_2
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Legitimate import of keys
  - Evernote
level: medium
tags:
  - attack.t1112
  - attack.defense_evasion

```
