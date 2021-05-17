---
title: "Suspicious Use of Procdump"
aliases:
  - "/rule/5afee48e-67dd-4e03-a783-f74259dcf998"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003
  - car.2013-05-009



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.

<!--more-->


## Known false-positives

* Unlikely, because no one should dump an lsass process memory
* Another tool that uses the command line switches of Procdump



## References

* Internal Research


## Raw rule
```yaml
title: Suspicious Use of Procdump
id: 5afee48e-67dd-4e03-a783-f74259dcf998
description: Detects suspicious uses of the SysInternals Procdump utility by using a special command line parameter in combination with the lsass.exe process. This way we're also able to catch cases in which the attacker has renamed the procdump executable.
status: experimental
references:
    - Internal Research
author: Florian Roth
date: 2018/10/30
modified: 2019/10/14
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003      # an old one     
    - car.2013-05-009
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '* -ma *'
    selection2:
        CommandLine:
            - '* lsass*'
    selection3:
        CommandLine:
            - '* -ma ls*'
    condition: ( selection1 and selection2 ) or selection3
falsepositives:
    - Unlikely, because no one should dump an lsass process memory
    - Another tool that uses the command line switches of Procdump
level: high

```
