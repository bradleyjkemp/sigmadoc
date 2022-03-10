---
title: "Suspicious Splwow64 Without Params"
aliases:
  - "/rule/1f1a8509-2cbb-44f5-8751-8e1571518ce2"


tags:
  - attack.defense_evasion
  - attack.t1202



status: experimental





date: Mon, 23 Aug 2021 10:41:42 +0200


---

Detects suspicious Splwow64.exe process without any command line parameters

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/sbousseaden/status/1429401053229891590?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_splwow64.yml))
```yaml
title: Suspicious Splwow64 Without Params
id: 1f1a8509-2cbb-44f5-8751-8e1571518ce2
status: experimental
description: Detects suspicious Splwow64.exe process without any command line parameters
references:
    - https://twitter.com/sbousseaden/status/1429401053229891590?s=12
author: Florian Roth
date: 2021/08/23
modified: 2021/11/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\splwow64.exe'
        CommandLine|endswith: 'splwow64.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion 
    - attack.t1202 
```
