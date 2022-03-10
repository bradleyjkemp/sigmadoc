---
title: "Google Cloud Storage Buckets Modified or Deleted"
aliases:
  - "/rule/4d9f2ee2-c903-48ab-b9c1-8c0f474913d0"


tags:
  - attack.impact



status: experimental





date: Sat, 14 Aug 2021 21:53:56 -0500


---

Detects when storage bucket is modified or deleted in Google Cloud.

<!--more-->


## Known false-positives

* Storage Buckets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Storage Buckets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://cloud.google.com/storage/docs/json_api/v1/buckets


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_bucket_modified_or_deleted.yml))
```yaml
title: Google Cloud Storage Buckets Modified or Deleted
id: 4d9f2ee2-c903-48ab-b9c1-8c0f474913d0
description: Detects when storage bucket is modified or deleted in Google Cloud.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/14
references:
    - https://cloud.google.com/storage/docs/json_api/v1/buckets
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - storage.buckets.delete
            - storage.buckets.insert
            - storage.buckets.update
            - storage.buckets.patch
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Storage Buckets being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Storage Buckets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
