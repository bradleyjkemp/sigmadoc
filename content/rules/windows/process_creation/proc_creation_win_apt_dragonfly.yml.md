---
title: "CrackMapExecWin"
aliases:
  - "/rule/04d9079e-3905-4b70-ad37-6bdf11304965"
ruleid: 04d9079e-3905-4b70-ad37-6bdf11304965

tags:
  - attack.g0035
  - attack.credential_access
  - attack.discovery
  - attack.t1110
  - attack.t1087



status: test





date: Sun, 8 Apr 2018 17:10:00 +0200


---

Detects CrackMapExecWin Activity as Described by NCSC

<!--more-->


## Known false-positives

* None



## References

* https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
* https://attack.mitre.org/software/S0488/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_dragonfly.yml))
```yaml
title: CrackMapExecWin
id: 04d9079e-3905-4b70-ad37-6bdf11304965
status: test
description: Detects CrackMapExecWin Activity as Described by NCSC
author: Markus Neis
references:
  - https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control
  - https://attack.mitre.org/software/S0488/
date: 2018/04/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\crackmapexec.exe'
  condition: selection
falsepositives:
  - None
level: critical
tags:
  - attack.g0035
  - attack.credential_access
  - attack.discovery
  - attack.t1110
  - attack.t1087

```
