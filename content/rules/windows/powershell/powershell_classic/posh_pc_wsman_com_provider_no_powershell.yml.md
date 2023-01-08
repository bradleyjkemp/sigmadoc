---
title: "Suspicious Non PowerShell WSMAN COM Provider"
aliases:
  - "/rule/df9a0e0e-fedb-4d6c-8668-d765dfc92aa7"
ruleid: df9a0e0e-fedb-4d6c-8668-d765dfc92aa7

tags:
  - attack.execution
  - attack.t1059.001
  - attack.lateral_movement
  - attack.t1021.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/chadtilbury/status/1275851297770610688
* https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
* https://github.com/bohops/WSMan-WinRM


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_wsman_com_provider_no_powershell.yml))
```yaml
title: Suspicious Non PowerShell WSMAN COM Provider
id: df9a0e0e-fedb-4d6c-8668-d765dfc92aa7
description: Detects suspicious use of the WSMAN provider without PowerShell.exe as the host application.
status: experimental
date: 2020/06/24
modified: 2021/08/30
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.execution
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.003
references:
    - https://twitter.com/chadtilbury/status/1275851297770610688
    - https://bohops.com/2020/05/12/ws-management-com-another-approach-for-winrm-lateral-movement/
    - https://github.com/bohops/WSMan-WinRM
logsource:
    product: windows
    service: powershell-classic
    definition: fields have to be extract from event
detection:
    selection:
        ProviderName: WSMan
    filter:
        HostApplication|contains: powershell
    condition: selection and not filter
falsepositives:
 - Unknown
level: medium

```
