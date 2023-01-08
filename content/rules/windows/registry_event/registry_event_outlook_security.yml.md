---
title: "Change Outlook Security Setting in Registry"
aliases:
  - "/rule/c3cefdf4-6703-4e1c-bad8-bf422fc5015a"
ruleid: c3cefdf4-6703-4e1c-bad8-bf422fc5015a

tags:
  - attack.persistence
  - attack.t1137



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Change outlook email security settings

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137/T1137.md
* https://docs.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_outlook_security.yml))
```yaml
title: Change Outlook Security Setting in Registry
id: c3cefdf4-6703-4e1c-bad8-bf422fc5015a
description: Change outlook email security settings
author: frack113
date: 2021/12/28
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1137/T1137.md
    - https://docs.microsoft.com/en-us/outlook/troubleshoot/security/information-about-email-security-settings
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject|contains|all:
            - '\SOFTWARE\Microsoft\Office\'
            - '\Outlook\Security\'
        EventType: SetValue
    condition: selection
falsepositives:
    - Administrative scripts
level: medium
tags:
  - attack.persistence
  - attack.t1137

```
