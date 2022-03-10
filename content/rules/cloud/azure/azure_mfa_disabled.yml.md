---
title: "Disabled MFA to Bypass Authentication Mechanisms"
aliases:
  - "/rule/7ea78478-a4f9-42a6-9dcd-f861816122bf"


tags:
  - attack.persistence
  - attack.t1556



status: experimental





date: Tue, 8 Feb 2022 10:19:09 +0100


---

Detection for when multi factor authentication has been disabled, which might indicate a malicious activity to bypass authentication mechanisms.

<!--more-->


## Known false-positives

* Authorized modification by administrators



## References

* https://attack.mitre.org/techniques/T1556/
* https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_mfa_disabled.yml))
```yaml
title: Disabled MFA to Bypass Authentication Mechanisms
id: 7ea78478-a4f9-42a6-9dcd-f861816122bf
status: experimental
description: Detection for when multi factor authentication has been disabled, which might indicate a malicious activity to bypass authentication mechanisms.
author: '@ionsor'
date: 2022/02/08
references:
    - https://attack.mitre.org/techniques/T1556/
    - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates
logsource:
    category: azure
    product: azure.activitylogs
detection:
    selection:
        eventSource: AzureActiveDirectory
        eventName: 'Disable Strong Authentication.'
        status: success
    condition: selection
falsepositives:
    - Authorized modification by administrators
level: medium
tags:
    - attack.persistence
    - attack.t1556

```
