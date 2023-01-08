---
title: "Google Cloud Service Account Disabled or Deleted"
aliases:
  - "/rule/13f81a90-a69c-4fab-8f07-b5bb55416a9f"
ruleid: 13f81a90-a69c-4fab-8f07-b5bb55416a9f

tags:
  - attack.impact
  - attack.t1531



status: experimental





date: Sat, 14 Aug 2021 22:26:21 -0500


---

Identifies when a service account is disabled or deleted in Google Cloud.

<!--more-->


## Known false-positives

* Service Account being disabled or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Service Account disabled or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_service_account_disabled_or_deleted.yml))
```yaml
title: Google Cloud Service Account Disabled or Deleted
id: 13f81a90-a69c-4fab-8f07-b5bb55416a9f
description: Identifies when a service account is disabled or deleted in Google Cloud. 
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
            - .serviceAccounts.disable
            - .serviceAccounts.delete
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.t1531
falsepositives:
 - Service Account being disabled or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Service Account disabled or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
