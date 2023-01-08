---
title: "ADCSPwn Hack Tool"
aliases:
  - "/rule/cd8c163e-a19b-402e-bdd5-419ff5859f12"
ruleid: cd8c163e-a19b-402e-bdd5-419ff5859f12

tags:
  - attack.credential_access
  - attack.t1557.001



status: test





date: Sat, 31 Jul 2021 10:18:21 +0200


---

Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service

<!--more-->


## Known false-positives

* unlikely



## References

* https://github.com/bats3c/ADCSPwn


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_hack_adcspwn.yml))
```yaml
title: ADCSPwn Hack Tool
id: cd8c163e-a19b-402e-bdd5-419ff5859f12
description: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
status: test
author: Florian Roth
references:
    - https://github.com/bats3c/ADCSPwn
date: 2021/07/31
tags:
    - attack.credential_access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' --adcs '
            - ' --port '
    condition: selection
falsepositives:
    - unlikely
level: critical

```
