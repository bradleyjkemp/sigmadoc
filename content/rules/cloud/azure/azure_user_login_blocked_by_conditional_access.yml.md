---
title: "User Access Blocked by Azure Conditional Access"
aliases:
  - "/rule/9a60e676-26ac-44c3-814b-0c2a8b977adf"
ruleid: 9a60e676-26ac-44c3-814b-0c2a8b977adf

tags:
  - attack.credential_access
  - attack.t1110



status: experimental





date: Sun, 10 Oct 2021 16:06:28 +0400


---

Detect access has been blocked by Conditional Access policies. The access policy does not allow token issuance which might be sights≈ of unauthorizeed login to valid accounts.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_user_login_blocked_by_conditional_access.yml))
```yaml
title: User Access Blocked by Azure Conditional Access
id: 9a60e676-26ac-44c3-814b-0c2a8b977adf
status: experimental
author: AlertIQ
date: 2021/10/10  
description: Detect access has been blocked by Conditional Access policies. The access policy does not allow token issuance which might be sights≈ of unauthorizeed login to valid accounts.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.signinlogs
detection:
  selection:
    ResultType: 53003
  condition: selection 
level: medium
falsepositives:
  - Unknown
tags:
  - attack.credential_access
  - attack.t1110

```
