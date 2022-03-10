---
title: "Suspicious PsExec Execution"
aliases:
  - "/rule/c462f537-a1e3-41a6-b5fc-b2c2cef9bf82"


tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Wed, 3 Apr 2019 15:59:46 +0200


---

detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one

<!--more-->


## Known false-positives

* nothing observed so far



## References

* https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_psexec.yml))
```yaml
title: Suspicious PsExec Execution
id: c462f537-a1e3-41a6-b5fc-b2c2cef9bf82
status: test
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: Samir Bousseaden
references:
  - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
date: 2019/04/03
modified: 2021/12/08
logsource:
  product: windows
  service: security
  definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
  selection1:
    EventID: 5145
    ShareName: \\\*\IPC$
    RelativeTargetName|endswith:
      - '-stdin'
      - '-stdout'
      - '-stderr'
  filter:
    RelativeTargetName|startswith: 'PSEXESVC'
  condition: selection1 and not filter
falsepositives:
  - nothing observed so far
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002

```
