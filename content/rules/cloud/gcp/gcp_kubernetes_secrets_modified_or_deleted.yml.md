---
title: "Google Cloud Kubernetes Secrets Modified or Deleted"
aliases:
  - "/rule/2f0bae2d-bf20-4465-be86-1311addebaa3"
ruleid: 2f0bae2d-bf20-4465-be86-1311addebaa3

tags:
  - attack.credential_access



status: experimental





date: Mon, 9 Aug 2021 22:08:14 -0500


---

Identifies when the Secrets are Modified or Deleted.

<!--more-->


## Known false-positives

* Secrets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_kubernetes_secrets_modified_or_deleted.yml))
```yaml
title: Google Cloud Kubernetes Secrets Modified or Deleted
id: 2f0bae2d-bf20-4465-be86-1311addebaa3
description: Identifies when the Secrets are Modified or Deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/09
references:
    - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - io.k8s.core.v*.secrets.create
            - io.k8s.core.v*.secrets.update
            - io.k8s.core.v*.secrets.patch
            - io.k8s.core.v*.secrets.delete 
    condition: selection
level: medium
tags:
    - attack.credential_access
falsepositives:
 - Secrets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```