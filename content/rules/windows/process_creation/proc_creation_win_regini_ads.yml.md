---
title: "Modifies the Registry From a ADS"
aliases:
  - "/rule/77946e79-97f1-45a2-84b4-f37b5c0d8682"


tags:
  - attack.t1112
  - attack.defense_evasion



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regini.yml
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_regini_ads.yml))
```yaml
title: Modifies the Registry From a ADS
id: 77946e79-97f1-45a2-84b4-f37b5c0d8682
status: experimental
description: Detects the import of an alternate data stream with regini.exe, regini.exe can be used to modify registry keys.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Regini.yml
    - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regini
tags:
    - attack.t1112
    - attack.defense_evasion
author: Eli Salem, Sander Wiebing, oscd.community
date: 2020/10/12
modified: 2021/05/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regini.exe'
        CommandLine|re: ':[^ \\\\]'
    condition: selection
fields:
    - ParentImage
    - CommandLine
falsepositives:
    - Unknown
level: high
```
