---
title: "Google Cloud DNS Zone Modified or Deleted"
aliases:
  - "/rule/28268a8f-191f-4c17-85b2-f5aa4fa829c3"
ruleid: 28268a8f-191f-4c17-85b2-f5aa4fa829c3

tags:
  - attack.impact



status: experimental





date: Sun, 15 Aug 2021 14:30:23 -0500


---

Identifies when a DNS Zone is modified or deleted in Google Cloud.

<!--more-->


## Known false-positives

* Unknown



## References

* https://cloud.google.com/dns/docs/reference/v1/managedZones


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_dns_zone_modified_or_deleted.yml))
```yaml
title: Google Cloud DNS Zone Modified or Deleted
id: 28268a8f-191f-4c17-85b2-f5aa4fa829c3
description: Identifies when a DNS Zone is modified or deleted in Google Cloud. 
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/15
references:
    - https://cloud.google.com/dns/docs/reference/v1/managedZones
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - Dns.ManagedZones.Delete
            - Dns.ManagedZones.Update
            - Dns.ManagedZones.Patch
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown

```
