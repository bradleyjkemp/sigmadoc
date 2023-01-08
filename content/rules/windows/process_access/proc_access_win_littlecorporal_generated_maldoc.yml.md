---
title: "LittleCorporal Generated Maldoc Injection"
aliases:
  - "/rule/7bdde3bf-2a42-4c39-aa31-a92b3e17afac"
ruleid: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac

tags:
  - attack.execution
  - attack.t1204.002
  - attack.t1055.003



status: experimental





date: Mon, 9 Aug 2021 13:25:07 +0200


---

Detects the process injection of a LittleCorporal generated Maldoc.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/connormcgarr/LittleCorporal


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_littlecorporal_generated_maldoc.yml))
```yaml
title: LittleCorporal Generated Maldoc Injection
id: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac
description: Detects the process injection of a LittleCorporal generated Maldoc.
references:
    - https://github.com/connormcgarr/LittleCorporal
status: experimental
author: Christian Burkard
date: 2021/08/09
logsource:
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|endswith: 'winword.exe'
        CallTrace|contains|all:
            - ':\Windows\Microsoft.NET\Framework64\v2.'
            - 'UNKNOWN'
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.execution
    - attack.t1204.002
    - attack.t1055.003

```
