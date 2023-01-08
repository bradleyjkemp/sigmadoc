---
title: "Koadic Execution"
aliases:
  - "/rule/5cddf373-ef00-4112-ad72-960ac29bac34"
ruleid: 5cddf373-ef00-4112-ad72-960ac29bac34

tags:
  - attack.execution
  - attack.t1059.003
  - attack.t1059.005
  - attack.t1059.007



status: test





date: Sun, 16 Feb 2020 16:48:49 +0100


---

Detects command line parameters used by Koadic hack tool

<!--more-->


## Known false-positives

* Pentest



## References

* https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/
* https://github.com/zerosum0x0/koadic/blob/master/data/stager/js/stdlib.js#L955
* https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_koadic.yml))
```yaml
title: Koadic Execution
id: 5cddf373-ef00-4112-ad72-960ac29bac34
status: test
description: Detects command line parameters used by Koadic hack tool
author: wagga, Jonhnathan Ribeiro, oscd.community
references:
  - https://unit42.paloaltonetworks.com/unit42-sofacy-groups-parallel-attacks/
  - https://github.com/zerosum0x0/koadic/blob/master/data/stager/js/stdlib.js#L955
  - https://blog.f-secure.com/hunting-for-koadic-a-com-based-rootkit/
date: 2020/01/12
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - '/q'
      - '/c'
      - 'chcp'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Pentest
level: high
tags:
  - attack.execution
  - attack.t1059.003
  - attack.t1059.005
  - attack.t1059.007
```
