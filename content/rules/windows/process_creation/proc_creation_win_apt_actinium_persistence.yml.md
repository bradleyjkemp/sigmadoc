---
title: "Scheduled Task WScript VBScript"
aliases:
  - "/rule/e1118a8f-82f5-44b3-bb6b-8a284e5df602"
ruleid: e1118a8f-82f5-44b3-bb6b-8a284e5df602



status: experimental





date: Mon, 7 Feb 2022 15:43:30 +0100


---

Detects specific process parameters as used by ACTINIUM scheduled task persistence creation.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.microsoft.com/security/blog/2022/02/04/actinium-targets-ukrainian-organizations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_actinium_persistence.yml))
```yaml
title: Scheduled Task WScript VBScript
id: e1118a8f-82f5-44b3-bb6b-8a284e5df602
status: experimental
description: Detects specific process parameters as used by ACTINIUM scheduled task persistence creation.
author: Andreas Hunkeler (@Karneades)
references:
  - https://www.microsoft.com/security/blog/2022/02/04/actinium-targets-ukrainian-organizations
date: 2022/02/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'schtasks'
      - 'create'
      - 'wscript'
      - 'e:vbscript'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unlikely
level: high

```
