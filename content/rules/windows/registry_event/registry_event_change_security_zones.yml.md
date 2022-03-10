---
title: "IE Change Domain Zone"
aliases:
  - "/rule/45e112d0-7759-4c2a-aa36-9f8fb79d3393"


tags:
  - attack.persistence
  - attack.t1137



status: experimental





date: Sun, 23 Jan 2022 11:37:01 +0100


---

Hides the file extension through modification of the registry

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
* https://docs.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_change_security_zones.yml))
```yaml
title: IE Change Domain Zone
id: 45e112d0-7759-4c2a-aa36-9f8fb79d3393
description: Hides the file extension through modification of the registry
author: frack113
date: 2022/01/22
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1112/T1112.md#atomic-test-4---add-domain-to-trusted-sites-zone
    - https://docs.microsoft.com/en-us/troubleshoot/developer/browsers/security-privacy/ie-security-zones-registry-entries
logsource:
    category: registry_event
    product: windows
detection:
    selection_domains:
        EventType: SetValue
        TargetObject|contains: \SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\
    filter:
        Details:
            - DWORD (0x00000000) # My Computer
            - DWORD (0x00000001) # Local Intranet Zone
    condition: selection_domains
falsepositives:
    - Administrative scripts
level: medium
tags:
  - attack.persistence
  - attack.t1137

```
