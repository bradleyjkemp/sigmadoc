---
title: "Code Integrity Blocked Driver Load"
aliases:
  - "/rule/f8931561-97f5-4c46-907f-0a4a592e47a7"


tags:
  - attack.execution



status: experimental





date: Thu, 20 Jan 2022 09:45:00 +0100


---

Detects driver load events that got blocked by Windows code integrity checks

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/SBousseaden/status/1483810148602814466


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/code_integrity/win_codeintegrity_failed_driver_load.yml))
```yaml
title: Code Integrity Blocked Driver Load
id: f8931561-97f5-4c46-907f-0a4a592e47a7
description: Detects driver load events that got blocked by Windows code integrity checks
author: Florian Roth
status: experimental
references:
    - https://twitter.com/SBousseaden/status/1483810148602814466
date: 2022/01/20
tags:
    - attack.execution
logsource:
    product: windows
    service: codeintegrity-operational
detection:
    keywords:
        - 'that did not meet the Microsoft signing level requirements'
    condition: keywords
falsepositives:
    - Unknown
level: high
```
