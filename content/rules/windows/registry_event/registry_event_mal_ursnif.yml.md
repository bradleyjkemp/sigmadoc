---
title: "Ursnif"
aliases:
  - "/rule/21f17060-b282-4249-ade0-589ea3591558"
ruleid: 21f17060-b282-4249-ade0-589ea3591558

tags:
  - attack.execution
  - attack.t1112



status: experimental





date: Wed, 13 Feb 2019 15:22:57 -0600


---

Detects new registry key created by Ursnif malware.

<!--more-->


## Known false-positives

* Unknown



## References

* https://blog.yoroi.company/research/ursnif-long-live-the-steganography/
* https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_mal_ursnif.yml))
```yaml
title: Ursnif
id: 21f17060-b282-4249-ade0-589ea3591558
status: experimental
description: Detects new registry key created by Ursnif malware.
references:
    - https://blog.yoroi.company/research/ursnif-long-live-the-steganography/
    - https://blog.trendmicro.com/trendlabs-security-intelligence/phishing-campaign-uses-hijacked-emails-to-deliver-ursnif-by-replying-to-ongoing-threads/
tags:
    - attack.execution
    - attack.t1112
author: megan201296
date: 2019/02/13
modified: 2021/11/15
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: '\Software\AppDataLow\Software\Microsoft\'
    filter:
        TargetObject|contains:
            - '\SOFTWARE\AppDataLow\Software\Microsoft\Internet Explorer\'
            - '\SOFTWARE\AppDataLow\Software\Microsoft\RepService\'
            - '\SOFTWARE\AppDataLow\Software\Microsoft\IME\'
            - '\SOFTWARE\AppDataLow\Software\Microsoft\Edge\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```
