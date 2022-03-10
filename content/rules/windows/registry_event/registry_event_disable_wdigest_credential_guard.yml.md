---
title: "Wdigest CredGuard Registry Modification"
aliases:
  - "/rule/1a2d6c47-75b0-45bd-b133-2c0be75349fd"


tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects potential malicious modification of the property value of IsCredGuardEnabled from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to disable Cred Guard on a system. This is usually used with UseLogonCredential to manipulate the caching credentials.

<!--more-->


## Known false-positives

* Unknown



## References

* https://teamhydra.blog/2020/08/25/bypassing-credential-guard/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_disable_wdigest_credential_guard.yml))
```yaml
title: Wdigest CredGuard Registry Modification
id: 1a2d6c47-75b0-45bd-b133-2c0be75349fd
status: test
description: Detects potential malicious modification of the property value of IsCredGuardEnabled from HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest to disable Cred Guard on a system. This is usually used with UseLogonCredential to manipulate the caching credentials.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://teamhydra.blog/2020/08/25/bypassing-credential-guard/
date: 2019/08/25
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|endswith: '\IsCredGuardEnabled'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.t1112

```
