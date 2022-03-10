---
title: "Account Lockout"
aliases:
  - "/rule/2b7d6fc0-71ac-4cf7-8ed1-b5788ee5257a"


tags:
  - attack.credential_access
  - attack.t1110



status: experimental





date: Sun, 10 Oct 2021 16:06:28 +0400


---

Identifies user account which has been locked because the user tried to sign in too many times with an incorrect user ID or password.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_account_lockout.yml))
```yaml
title: Account Lockout 
id: 2b7d6fc0-71ac-4cf7-8ed1-b5788ee5257a
status: experimental
author: AlertIQ
date: 2021/10/10  
description: Identifies user account which has been locked because the user tried to sign in too many times with an incorrect user ID or password.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.signinlogs
detection:
  selection:
    ResultType: 50053
  condition: selection
level: medium
falsepositives:
  - Unknown
tags:
  - attack.credential_access
  - attack.t1110

```
