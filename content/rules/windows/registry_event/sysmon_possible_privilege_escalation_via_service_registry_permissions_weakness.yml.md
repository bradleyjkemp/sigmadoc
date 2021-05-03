---
title: "Possible Privilege Escalation via Service Permissions Weakness"
aliases:
  - "/rule/0f9c21f1-6a73-4b0e-9809-cb562cb8d981"

tags:
  - attack.privilege_escalation
  - attack.t1058
  - attack.t1574.011



date: Sun, 27 Oct 2019 20:54:07 +0300


---

Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
* https://pentestlab.blog/2017/03/31/insecure-registry-permissions/


## Raw rule
```yaml
title: Possible Privilege Escalation via Service Permissions Weakness
id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
tags:
    - attack.privilege_escalation
    - attack.t1058 # an old one
    - attack.t1574.011
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2020/09/06
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        
        IntegrityLevel: 'Medium'
        TargetObject|contains: '\services\'
        TargetObject|endswith:
            - '\ImagePath'
            - '\FailureCommand'
            - '\Parameters\ServiceDll'
    condition: selection
falsepositives:
    - Unknown
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                      # http://bit.ly/314zc6x
    - EN_0003_enrich_other_sysmon_events_with_event_id_1_data   # http://bit.ly/2ojW7fw

```