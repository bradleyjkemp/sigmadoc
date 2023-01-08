---
title: "Azure Application Credential Modified"
aliases:
  - "/rule/cdeef967-f9a1-4375-90ee-6978c5f23974"
ruleid: cdeef967-f9a1-4375-90ee-6978c5f23974

tags:
  - attack.impact



status: experimental





date: Thu, 2 Sep 2021 20:53:32 -0500


---

Identifies when a application credential is modified.

<!--more-->


## Known false-positives

* Application credential added may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Application credential added from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://www.cloud-architekt.net/auditing-of-msi-and-service-principals/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_app_credential_modification.yml))
```yaml
title: Azure Application Credential Modified
id: cdeef967-f9a1-4375-90ee-6978c5f23974
description: Identifies when a application credential is modified.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/02
references:
    - https://www.cloud-architekt.net/auditing-of-msi-and-service-principals/
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 'Update application - Certificates and secrets management'
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Application credential added may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Application credential added from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
