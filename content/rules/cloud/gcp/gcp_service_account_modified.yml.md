---
title: "Google Cloud Service Account Modified"
aliases:
  - "/rule/6b67c12e-5e40-47c6-b3b0-1e6b571184cc"


tags:
  - attack.impact



status: experimental





date: Sat, 14 Aug 2021 22:25:41 -0500


---

Identifies when a service account is modified in Google Cloud.

<!--more-->


## Known false-positives

* Service Account being modified may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Service Account modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_service_account_modified.yml))
```yaml
title: Google Cloud Service Account Modified
id: 6b67c12e-5e40-47c6-b3b0-1e6b571184cc
description: Identifies when a service account is modified in Google Cloud. 
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/14
references:
    - https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name|endswith: 
            - .serviceAccounts.patch
            - .serviceAccounts.create
            - .serviceAccounts.update
            - .serviceAccounts.enable
            - .serviceAccounts.undelete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Service Account being modified may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Service Account modified from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
