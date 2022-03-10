---
title: "Failed Code Integrity Checks"
aliases:
  - "/rule/470ec5fa-7b4e-4071-b200-4c753100f49b"


tags:
  - attack.defense_evasion
  - attack.t1027.001



status: stable





date: Tue, 3 Dec 2019 15:08:26 +0100


---

Code integrity failures may indicate tampered executables.

<!--more-->


## Known false-positives

* Disk device errors




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_codeintegrity_check_failure.yml))
```yaml
title: Failed Code Integrity Checks
id: 470ec5fa-7b4e-4071-b200-4c753100f49b
status: stable
description: Code integrity failures may indicate tampered executables.
author: Thomas Patzke
date: 2019/12/03
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.t1027.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5038
            - 6281
    condition: selection
falsepositives:
    - Disk device errors
level: low

```
