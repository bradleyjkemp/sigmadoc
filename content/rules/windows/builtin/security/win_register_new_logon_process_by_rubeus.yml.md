---
title: "Register new Logon Process by Rubeus"
aliases:
  - "/rule/12e6d621-194f-4f59-90cc-1959e21e69f7"
ruleid: 12e6d621-194f-4f59-90cc-1959e21e69f7

tags:
  - attack.lateral_movement
  - attack.privilege_escalation
  - attack.t1558.003



status: experimental





date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects potential use of Rubeus via registered new trusted logon process

<!--more-->


## Known false-positives

* Unknown



## References

* https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_register_new_logon_process_by_rubeus.yml))
```yaml
title: Register new Logon Process by Rubeus
id: 12e6d621-194f-4f59-90cc-1959e21e69f7
description: Detects potential use of Rubeus via registered new trusted logon process
status: experimental
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1558.003
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
modified: 2021/08/14
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4611
        LogonProcessName: 'User32LogonProcesss'
    condition: selection
falsepositives:
    - Unknown
level: critical

```
