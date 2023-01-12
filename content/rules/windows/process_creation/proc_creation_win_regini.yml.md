---
title: "Modifies the Registry From a File"
aliases:
  - "/rule/5f60740a-f57b-4e76-82a1-15b6ff2cb134"
ruleid: 5f60740a-f57b-4e76-82a1-15b6ff2cb134

tags:
  - attack.t1112
  - attack.defense_evasion



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.

<!--more-->


## Known false-positives

* Legitimate modification of keys



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regini.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regini.yml))
```yaml
title: Modifies the Registry From a File
id: 5f60740a-f57b-4e76-82a1-15b6ff2cb134
status: experimental
description: Detects the execution of regini.exe which can be used to modify registry keys, the changes are imported from one or more text files.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regini.yml
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini
tags:
    - attack.t1112
    - attack.defense_evasion
author: Eli Salem, Sander Wiebing, oscd.community
date: 2020/10/08
modified: 2021/05/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regini.exe'
    filter:
        CommandLine|re: ':[^ \\\\]' # to avoid intersection with ADS rule
    condition: selection and not filter
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Legitimate modification of keys
level: low
```