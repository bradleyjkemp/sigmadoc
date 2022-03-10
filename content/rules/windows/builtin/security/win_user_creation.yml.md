---
title: "Local User Creation"
aliases:
  - "/rule/66b6be3d-55d0-4f47-9855-d69df21740ea"


tags:
  - attack.persistence
  - attack.t1136.001



status: test





date: Thu, 18 Apr 2019 19:59:43 +0200


---

Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.

<!--more-->


## Known false-positives

* Domain Controller Logs
* Local accounts managed by privileged account management tools



## References

* https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_user_creation.yml))
```yaml
title: Local User Creation
id: 66b6be3d-55d0-4f47-9855-d69df21740ea
status: test
description: Detects local user creation on windows servers, which shouldn't happen in an Active Directory environment. Apply this Sigma Use Case on your windows server logs and not on your DC logs.
author: Patrick Bareiss
references:
  - https://patrick-bareiss.com/detecting-local-user-creation-in-ad-with-sigma/
date: 2019/04/18
modified: 2021/01/17
logsource:
  product: windows
  service: security
detection:
  selection:
    Provider_Name: Microsoft-Windows-Security-Auditing
    EventID: 4720
  condition: selection
fields:
  - EventCode
  - AccountName
  - AccountDomain
falsepositives:
  - Domain Controller Logs
  - Local accounts managed by privileged account management tools
level: low
tags:
  - attack.persistence
  - attack.t1136.001

```
