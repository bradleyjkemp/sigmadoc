---
title: "Change to Authentication Method"
aliases:
  - "/rule/4d78a000-ab52-4564-88a5-7ab5242b20c7"


tags:
  - attack.credential_access



status: experimental





date: Sun, 10 Oct 2021 16:06:28 +0400


---

Change to authentication method could be an indicated of an attacker adding an auth method to the account so they can have continued access.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_change_to_authentication_method.yml))
```yaml
title: Change to Authentication Method
id: 4d78a000-ab52-4564-88a5-7ab5242b20c7
status: experimental
author: AlertIQ
date: 2021/10/10  
description: Change to authentication method could be an indicated of an attacker adding an auth method to the account so they can have continued access.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.auditlogs
detection:
  selection:
    LoggedByService: 'Authentication Methods'
    Category: 'UserManagement'
    OperationName: 'User registered security info'
  condition: selection
level: medium
falsepositives:
  - Unknown
tags:
  - attack.credential_access

```
