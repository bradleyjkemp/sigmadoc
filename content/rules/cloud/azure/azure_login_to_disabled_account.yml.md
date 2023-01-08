---
title: "Login to Disabled Account"
aliases:
  - "/rule/908655e0-25cf-4ae1-b775-1c8ce9cf43d8"
ruleid: 908655e0-25cf-4ae1-b775-1c8ce9cf43d8

tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Sun, 10 Oct 2021 16:06:28 +0400


---

Detect failed attempts to sign in to disabled accounts.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_login_to_disabled_account.yml))
```yaml
title: Login to Disabled Account
id: 908655e0-25cf-4ae1-b775-1c8ce9cf43d8
status: experimental
author: AlertIQ
date: 2021/10/10  
description: Detect failed attempts to sign in to disabled accounts.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.signinlogs
detection:
  selection:
    ResultType: 50057
    ResultDescription: 'User account is disabled. The account has been disabled by an administrator.'
  condition: selection 
level: medium
falsepositives:
  - Unknown
tags:
  - attack.initial_access
  - attack.t1078

```
