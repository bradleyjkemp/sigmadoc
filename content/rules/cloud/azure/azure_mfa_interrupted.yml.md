---
title: "Multifactor Authentication Interupted"
aliases:
  - "/rule/5496ff55-42ec-4369-81cb-00f417029e25"


tags:
  - attack.initial_access
  - attack.t1078.004



status: experimental





date: Sun, 10 Oct 2021 16:06:28 +0400


---

Identifies user login with multifactor authentication failures, which might be an indication an attacker has the password for the account but can't pass the MFA challenge.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_mfa_interrupted.yml))
```yaml
title: Multifactor Authentication Interupted
id: 5496ff55-42ec-4369-81cb-00f417029e25
status: experimental
author: AlertIQ
date: 2021/10/10  
description: Identifies user login with multifactor authentication failures, which might be an indication an attacker has the password for the account but can't pass the MFA challenge.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.signinlogs
detection:
  selection:
    ResultType: 50074
    ResultDescription|contains: 'Strong Auth required'
  selection1:
    ResultType: 500121
    ResultDescription|contains: 'Authentication failed during strong authentication request'
  condition: selection or selection1
level: medium
falsepositives:
  - Unknown
tags:
  - attack.initial_access
  - attack.t1078.004

```
