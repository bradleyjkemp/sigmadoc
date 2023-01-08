---
title: "Empire PowerShell Launch Parameters"
aliases:
  - "/rule/79f4ede3-402e-41c8-bc3e-ebbf5f162581"
ruleid: 79f4ede3-402e-41c8-bc3e-ebbf5f162581

tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Sat, 20 Apr 2019 09:38:30 +0200


---

Detects suspicious powershell command line parameters used in Empire

<!--more-->


## Known false-positives

* Other tools that incidentally use the same command line parameters



## References

* https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_powershell_empire_launch.yml))
```yaml
title: Empire PowerShell Launch Parameters
id: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
status: test
description: Detects suspicious powershell command line parameters used in Empire
author: Florian Roth
references:
  - https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
date: 2019/04/20
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - ' -NoP -sta -NonI -W Hidden -Enc '
      - ' -noP -sta -w 1 -enc '
      - ' -NoP -NonI -W Hidden -enc '
      - ' -noP -sta -w 1 -enc'
      - ' -enc  SQB'
      - ' -nop -exec bypass -EncodedCommand '
  condition: selection
falsepositives:
  - Other tools that incidentally use the same command line parameters
level: critical
tags:
  - attack.execution
  - attack.t1059.001

```
