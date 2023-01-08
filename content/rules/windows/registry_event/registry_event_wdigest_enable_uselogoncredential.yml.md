---
title: "Wdigest Enable UseLogonCredential"
aliases:
  - "/rule/d6a9b252-c666-4de6-8806-5561bbbd3bdc"
ruleid: d6a9b252-c666-4de6-8806-5561bbbd3bdc

tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html
* https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_wdigest_enable_uselogoncredential.yml))
```yaml
title: Wdigest Enable UseLogonCredential
id: d6a9b252-c666-4de6-8806-5561bbbd3bdc
description: Detects potential malicious modification of the property value of UseLogonCredential from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to enable clear-text credentials
status: experimental
date: 2019/09/12
modified: 2022/02/01
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.defense_evasion
    - attack.t1112
references:
    - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html
    - https://support.microsoft.com/en-us/topic/microsoft-security-advisory-update-to-improve-credentials-protection-and-management-may-13-2014-93434251-04ac-b7f3-52aa-9f951c14b649
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|endswith: 'WDigest\UseLogonCredential'
        Details: DWORD (0x00000001) 
    condition: selection
falsepositives:
    - Unknown
level: high

```
