---
title: "Potential Remote Desktop Connection to Non-Domain Host"
aliases:
  - "/rule/ce5678bb-b9aa-4fb5-be4b-e57f686256ad"
ruleid: ce5678bb-b9aa-4fb5-be4b-e57f686256ad

tags:
  - attack.command_and_control
  - attack.t1219



status: test





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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/ntlm/win_susp_ntlm_rdp.yml))
```yaml
title: Potential Remote Desktop Connection to Non-Domain Host
id: ce5678bb-b9aa-4fb5-be4b-e57f686256ad
status: test
description: Detects logons using NTLM to hosts that are potentially not part of the domain.
author: James Pemberton
references:
  - n/a
date: 2020/05/22
modified: 2021/11/27
logsource:
  product: windows
  service: ntlm
  definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
  selection:
    EventID: 8001
    TargetName|startswith: TERMSRV
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
tags:
  - attack.command_and_control
  - attack.t1219

```
