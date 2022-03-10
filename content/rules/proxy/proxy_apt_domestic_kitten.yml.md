---
title: "Domestic Kitten FurBall Malware Pattern"
aliases:
  - "/rule/6c939dfa-c710-4e12-a4dd-47e1f10e68e1"


tags:
  - attack.command_and_control



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects specific malware patterns used by FurBall malware linked to Iranian Domestic Kitten APT group

<!--more-->


## Known false-positives

* Unlikely



## References

* https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_apt_domestic_kitten.yml))
```yaml
title: Domestic Kitten FurBall Malware Pattern
id: 6c939dfa-c710-4e12-a4dd-47e1f10e68e1
status: experimental
description: Detects specific malware patterns used by FurBall malware linked to Iranian Domestic Kitten APT group
author: Florian Roth
references:
    - https://research.checkpoint.com/2021/domestic-kitten-an-inside-look-at-the-iranian-surveillance-operations/
date: 2021/02/08
tags:
    - attack.command_and_control
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 
            - 'Get~~~AllBrowser'
            - 'Get~~~HardwareInfo'
            - 'Take~~RecordCall'
            - 'Reset~~~AllCommand'
    condition: selection
fields:
    - c-ip
    - c-uri
falsepositives:
    - Unlikely
level: high

```
