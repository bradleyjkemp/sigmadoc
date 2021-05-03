---
title: "Potential Remote Desktop Connection to Non-Domain Host"
aliases:
  - "/rule/ce5678bb-b9aa-4fb5-be4b-e57f686256ad"

tags:
  - attack.command_and_control
  - attack.t1219



date: Fri, 22 May 2020 13:24:27 +1000


---

Detects logons using NTLM to hosts that are potentially not part of the domain.

<!--more-->


## Known false-positives

* Host connections to valid domains, exclude these.
* Host connections not using host FQDN.
* Host connections to external legitimate domains.



## References

* n/a


## Raw rule
```yaml
title: Potential Remote Desktop Connection to Non-Domain Host
id: ce5678bb-b9aa-4fb5-be4b-e57f686256ad
status: experimental
description: Detects logons using NTLM to hosts that are potentially not part of the domain.
references:
    - n/a
author: James Pemberton
date: 2020/05/22
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8001
        TargetName: TERMSRV*
    condition: selection
fields:
    - Computer
    - UserName
    - DomainName
    - TargetName
falsepositives:
    - Host connections to valid domains, exclude these.
    - Host connections not using host FQDN.
    - Host connections to external legitimate domains.
level: medium

```