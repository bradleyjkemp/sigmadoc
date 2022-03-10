---
title: "Renamed jusched.exe"
aliases:
  - "/rule/edd8a48c-1b9f-4ba1-83aa-490338cd1ccb"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1036.003



status: test





date: Thu, 6 Jun 2019 14:03:02 +0200


---

Detects renamed jusched.exe used by cobalt group

<!--more-->


## Known false-positives

* penetration tests, red teaming



## References

* https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_renamed_jusched.yml))
```yaml
title: Renamed jusched.exe
id: edd8a48c-1b9f-4ba1-83aa-490338cd1ccb
status: test
description: Detects renamed jusched.exe used by cobalt group
author: Markus Neis, Swisscom
references:
  - https://www.bitdefender.com/files/News/CaseStudies/study/262/Bitdefender-WhitePaper-An-APT-Blueprint-Gaining-New-Visibility-into-Financial-Threats-interactive.pdf
date: 2019/06/04
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Description: Java Update Scheduler
  selection2:
    Description: Java(TM) Update Scheduler
  filter:
    Image|endswith:
      - '\jusched.exe'
  condition: (selection1 or selection2) and not filter
falsepositives:
  - penetration tests, red teaming
level: high
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1036.003

```
