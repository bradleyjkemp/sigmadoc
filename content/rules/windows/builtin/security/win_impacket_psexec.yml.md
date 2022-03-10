---
title: "Impacket PsExec Execution"
aliases:
  - "/rule/32d56ea1-417f-44ff-822b-882873f5f43b"


tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Mon, 14 Dec 2020 12:48:26 +0545


---

Detects execution of Impacket's psexec.py.

<!--more-->


## Known false-positives

* nothing observed so far



## References

* https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_impacket_psexec.yml))
```yaml
title: Impacket PsExec Execution
id: 32d56ea1-417f-44ff-822b-882873f5f43b
status: test
description: Detects execution of Impacket's psexec.py.
author: Bhabesh Raj
references:
  - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
date: 2020/12/14
modified: 2022/01/07
logsource:
  product: windows
  service: security
  definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
  selection1:
    EventID: 5145
    ShareName: \\\*\IPC$
    RelativeTargetName|contains:
      - 'RemCom_stdint'
      - 'RemCom_stdoutt'
      - 'RemCom_stderrt'
  condition: selection1
falsepositives:
  - nothing observed so far
level: high
tags:
  - attack.lateral_movement
  - attack.t1021.002

```
