---
title: "CrackMapExecWin"
aliases:
  - "/rule/04d9079e-3905-4b70-ad37-6bdf11304965"

tags:
  - attack.g0035



status: experimental



level: critical



date: Sun, 8 Apr 2018 17:10:00 +0200


---

Detects CrackMapExecWin Activity as Described by NCSC

<!--more-->


## Known false-positives

* None



## References

* https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control


## Raw rule
```yaml
title: CrackMapExecWin
id: 04d9079e-3905-4b70-ad37-6bdf11304965
description: Detects CrackMapExecWin Activity as Described by NCSC
status: experimental
references:
    - https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
tags:
    - attack.g0035
author: Markus Neis
date: 2018/04/08
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\crackmapexec.exe'
    condition: selection
falsepositives:
    - None
level: critical

```
