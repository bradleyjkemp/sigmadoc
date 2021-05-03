---
title: "Detection of Possible Rotten Potato"
aliases:
  - "/rule/6c5808ee-85a2-4e56-8137-72e5876a5096"

tags:
  - attack.privilege_escalation
  - attack.t1134
  - attack.t1134.002



date: Sun, 27 Oct 2019 20:54:07 +0300


---

Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE privileges

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
* https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/


## Raw rule
```yaml
title: Detection of Possible Rotten Potato
id: 6c5808ee-85a2-4e56-8137-72e5876a5096
description: Detection of child processes spawned with SYSTEM privileges by parents with LOCAL SERVICE or NETWORK SERVICE privileges
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
tags:
    - attack.privilege_escalation
    - attack.t1134           # an old one
    - attack.t1134.002
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentUser:
            - 'NT AUTHORITY\NETWORK SERVICE'
            - 'NT AUTHORITY\LOCAL SERVICE'
        User: 'NT AUTHORITY\SYSTEM'
    rundllexception:
        Image|endswith: '\rundll32.exe'
        CommandLine|contains: 'DavSetCookie'
    condition: selection and not rundllexception
falsepositives:
    - Unknown
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                # http://bit.ly/314zc6x
    - EN_0002_enrich_sysmon_event_id_1_with_parent_info   # http://bit.ly/2KmSC0l

```