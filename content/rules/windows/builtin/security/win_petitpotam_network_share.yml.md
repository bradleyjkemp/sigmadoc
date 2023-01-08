---
title: "Possible PetitPotam Coerce Authentication Attempt"
aliases:
  - "/rule/1ce8c8a3-2723-48ed-8246-906ac91061a6"
ruleid: 1ce8c8a3-2723-48ed-8246-906ac91061a6

tags:
  - attack.credential_access
  - attack.t1187



status: experimental





date: Fri, 3 Sep 2021 00:12:49 -0400


---

Detect PetitPotam coerced authentication activity.

<!--more-->


## Known false-positives

* Unknown. Feedback welcomed.



## References

* https://github.com/topotam/PetitPotam
* https://github.com/splunk/security_content/blob/0dd6de32de2118b2818550df9e65255f4109a56d/detections/endpoint/petitpotam_network_share_access_request.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_petitpotam_network_share.yml))
```yaml
title: Possible PetitPotam Coerce Authentication Attempt
id: 1ce8c8a3-2723-48ed-8246-906ac91061a6
description: Detect PetitPotam coerced authentication activity.
status: experimental
author: Mauricio Velazco, Michael Haag
date: 2021/09/02
references:
    - https://github.com/topotam/PetitPotam
    - https://github.com/splunk/security_content/blob/0dd6de32de2118b2818550df9e65255f4109a56d/detections/endpoint/petitpotam_network_share_access_request.yml
tags:
    - attack.credential_access
    - attack.t1187
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName|startswith: '\\'
        ShareName|endswith: '\IPC$'
        RelativeTargetName: lsarpc
        SubjectUserName: ANONYMOUS LOGON
    condition: selection
falsepositives:
    - Unknown. Feedback welcomed.
level: high

```
