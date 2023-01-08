---
title: "Imports Registry Key From an ADS"
aliases:
  - "/rule/0b80ade5-6997-4b1d-99a1-71701778ea61"
ruleid: 0b80ade5-6997-4b1d-99a1-71701778ea61

tags:
  - attack.t1112
  - attack.defense_evasion



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the import of a alternate datastream to the registry with regedit.exe.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regedit.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regedit_import_keys_ads.yml))
```yaml
title: Imports Registry Key From an ADS
id: 0b80ade5-6997-4b1d-99a1-71701778ea61
status: test
description: Detects the import of a alternate datastream to the registry with regedit.exe.
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
    CommandLine|contains:
      - ' /i '
      - '.reg'
  selection_2:
    CommandLine|re: ':[^ \\\\]'
  filter:
    CommandLine|contains:
      - ' /e '
      - ' /a '
      - ' /c '
  condition: selection and selection_2 and not filter
fields:
  - ParentImage
  - CommandLine
falsepositives:
  - Unknown
level: high
tags:
  - attack.t1112
  - attack.defense_evasion

```
