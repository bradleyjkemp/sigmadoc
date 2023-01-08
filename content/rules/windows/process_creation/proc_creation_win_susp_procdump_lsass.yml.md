---
title: "Suspicious Use of Procdump on LSASS"
aliases:
  - "/rule/5afee48e-67dd-4e03-a783-f74259dcf998"
ruleid: 5afee48e-67dd-4e03-a783-f74259dcf998

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.credential_access
  - attack.t1003.001
  - car.2013-05-009



status: stable





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.

<!--more-->


## Known false-positives

* Unlikely, because no one should dump an lsass process memory
* Another tool that uses the command line switches of Procdump



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_procdump_lsass.yml))
```yaml
title: Suspicious Use of Procdump on LSASS
id: 5afee48e-67dd-4e03-a783-f74259dcf998
description: Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
status: stable
references:
    - Internal Research
author: Florian Roth
date: 2018/10/30
modified: 2021/02/02
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003.001
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: ' -ma '
    selection2:
        CommandLine|contains: ' lsass'
    selection3:
        CommandLine|contains|all:
            - ' -ma '
            - ' ls'
    condition: ( selection1 and selection2 ) or selection3
falsepositives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses the command line switches of Procdump
level: critical

```
