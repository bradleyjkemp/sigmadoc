---
title: "Google Cloud Firewall Modified or Deleted"
aliases:
  - "/rule/fe513c69-734c-4d4a-8548-ac5f609be82b"
ruleid: fe513c69-734c-4d4a-8548-ac5f609be82b

tags:
  - attack.defense_evasion
  - attack.t1562



status: experimental





date: Fri, 13 Aug 2021 16:50:34 -0500


---

Detects  when a firewall rule is modified or deleted in Google Cloud Platform (GCP).

<!--more-->


## Known false-positives

* Firewall rules being modified or deleted may be performed by a system administrator. Verify that the firewall configuration change was expected.
* Exceptions can be added to this rule to filter expected behavior.



## References

* https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
* https://developers.google.com/resources/api-libraries/documentation/compute/v1/java/latest/com/google/api/services/compute/Compute.Firewalls.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_firewall_rule_modified_or_deleted.yml))
```yaml
title: Google Cloud Firewall Modified or Deleted
id: fe513c69-734c-4d4a-8548-ac5f609be82b
description: Detects  when a firewall rule is modified or deleted in Google Cloud Platform (GCP).
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/13
references:
    - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
    - https://developers.google.com/resources/api-libraries/documentation/compute/v1/java/latest/com/google/api/services/compute/Compute.Firewalls.html
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - v*.Compute.Firewalls.Delete
            - v*.Compute.Firewalls.Patch
            - v*.Compute.Firewalls.Update
            - v*.Compute.Firewalls.Insert
    condition: selection
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562
falsepositives:
 - Firewall rules being modified or deleted may be performed by a system administrator. Verify that the firewall configuration change was expected. 
 - Exceptions can be added to this rule to filter expected behavior.

```
