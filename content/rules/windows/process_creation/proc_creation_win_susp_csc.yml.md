---
title: "Suspicious Parent of Csc.exe"
aliases:
  - "/rule/b730a276-6b63-41b8-bcf8-55930c8fc6ee"
ruleid: b730a276-6b63-41b8-bcf8-55930c8fc6ee

tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  - attack.defense_evasion
  - attack.t1218.005
  - attack.t1027.004



status: test





---

Detects a suspicious parent of csc.exe, which could by a sign of payload delivery

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/SBousseaden/status/1094924091256176641


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_csc.yml))
```yaml
title: Suspicious Parent of Csc.exe
id: b730a276-6b63-41b8-bcf8-55930c8fc6ee
status: test
description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
author: Florian Roth
references:
  - https://twitter.com/SBousseaden/status/1094924091256176641
date: 2019/02/11
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\csc.exe'
    ParentImage|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  - attack.defense_evasion
  - attack.t1218.005
  - attack.t1027.004

```
