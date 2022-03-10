---
title: "Azure Domain Federation Settings Modified"
aliases:
  - "/rule/352a54e1-74ba-4929-9d47-8193d67aba1e"


tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Mon, 6 Sep 2021 11:06:58 -0500


---

Identifies when an user or application modified the federation settings on the domain.

<!--more-->


## Known false-positives

* Federation Settings being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Federation Settings modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://attack.mitre.org/techniques/T1078


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_federation_modified.yml))
```yaml
title: Azure Domain Federation Settings Modified
id: 352a54e1-74ba-4929-9d47-8193d67aba1e
description: Identifies when an user or application modified the federation settings on the domain.
author: Austin Songer
status: experimental
date: 2021/09/06
references:
    - https://attack.mitre.org/techniques/T1078
logsource:
  product: azure
  service: azure.signinlogs
detection:
    selection:
        properties.message: Set federation settings on domain
    condition: selection
level: medium
tags:
    - attack.initial_access
    - attack.t1078
falsepositives:
 - Federation Settings being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Federation Settings modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.


```
