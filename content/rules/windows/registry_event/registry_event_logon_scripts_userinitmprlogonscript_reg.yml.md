---
title: "Logon Scripts (UserInitMprLogonScript) Registry"
aliases:
  - "/rule/9ace0707-b560-49b8-b6ca-5148b42f39fb"
ruleid: 9ace0707-b560-49b8-b6ca-5148b42f39fb

tags:
  - attack.t1037.001
  - attack.persistence
  - attack.lateral_movement



status: test





date: Wed, 1 Jul 2020 10:58:39 +0200


---

Detects creation or execution of UserInitMprLogonScript persistence method

<!--more-->


## Known false-positives

* exclude legitimate logon scripts
* penetration tests, red teaming



## References

* https://attack.mitre.org/techniques/T1037/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_logon_scripts_userinitmprlogonscript_reg.yml))
```yaml
title: Logon Scripts (UserInitMprLogonScript) Registry
id: 9ace0707-b560-49b8-b6ca-5148b42f39fb
status: test
description: Detects creation or execution of UserInitMprLogonScript persistence method
author: Tom Ueltschi (@c_APT_ure)
references:
  - https://attack.mitre.org/techniques/T1037/
date: 2019/01/12
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  create_keywords_reg:
    TargetObject|contains: 'UserInitMprLogonScript'
  condition: create_keywords_reg
falsepositives:
  - exclude legitimate logon scripts
  - penetration tests, red teaming
level: high
tags:
  - attack.t1037.001
  - attack.persistence
  - attack.lateral_movement

```
