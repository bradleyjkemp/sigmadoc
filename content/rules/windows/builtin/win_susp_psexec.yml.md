---
title: "Suspicious PsExec Execution"
aliases:
  - "/rule/c462f537-a1e3-41a6-b5fc-b2c2cef9bf82"

tags:
  - attack.lateral_movement
  - attack.t1077
  - attack.t1021.002



date: Wed, 3 Apr 2019 15:59:46 +0200


---

detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

<!--more-->


## Known false-positives

* nothing observed so far



## References

* https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html


## Raw rule
```yaml
title: Suspicious PsExec Execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077           # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
            - '*-stdin'
            - '*-stdout'
            - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives:
    - nothing observed so far
level: high

```