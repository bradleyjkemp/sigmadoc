---
title: "TAIDOOR RAT DLL Load"
aliases:
  - "/rule/d1aa3382-abab-446f-96ea-4de52908210b"
ruleid: d1aa3382-abab-446f-96ea-4de52908210b

tags:
  - attack.execution
  - attack.t1055.001



status: test





date: Tue, 4 Aug 2020 14:31:20 +0200


---

Detects specific process characteristics of Chinese TAIDOOR RAT malware load

<!--more-->


## Known false-positives

* Unknown



## References

* https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_taidoor.yml))
```yaml
title: TAIDOOR RAT DLL Load
id: d1aa3382-abab-446f-96ea-4de52908210b
status: test
description: Detects specific process characteristics of Chinese TAIDOOR RAT malware load
author: Florian Roth
references:
  - https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a
date: 2020/07/30
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains:
      - 'dll,MyStart'
      - 'dll MyStart'
  selection2a:
    CommandLine|endswith:
      - ' MyStart'
  selection2b:
    CommandLine|contains:
      - 'rundll32.exe'
  condition: selection1 or ( selection2a and selection2b )
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.t1055.001

```
