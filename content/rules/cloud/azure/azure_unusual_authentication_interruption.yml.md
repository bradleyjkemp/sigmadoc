---
title: "Azure Unusual Authentication Interruption"
aliases:
  - "/rule/8366030e-7216-476b-9927-271d79f13cf3"


tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Fri, 26 Nov 2021 11:07:53 -0600


---

Detects when there is a interruption in the authentication process.

<!--more-->


## Known false-positives

* Unknown



## References

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_unusual_authentication_interruption.yml))
```yaml
title: Azure Unusual Authentication Interruption
id: 8366030e-7216-476b-9927-271d79f13cf3
status: experimental
author: Austin Songer @austinsonger
date: 2021/11/26  
description: Detects when there is a interruption in the authentication process.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts
logsource:
  product: azure
  service: azure.signinlogs
detection:
    selection1:
          ResultType: 50097
          ResultDescription: 'Device authentication is required'
    selection2:
          ResultType: 50155
          ResultDescription: 'DeviceAuthenticationFailed'
    selection3:
          ResultType: 50158
          ResultDescription: 'ExternalSecurityChallenge - External security challenge was not satisfied'
    condition: selection1 or selection2 or selection3 
level: medium
falsepositives:
  - Unknown
tags:
  - attack.initial_access
  - attack.t1078

```
