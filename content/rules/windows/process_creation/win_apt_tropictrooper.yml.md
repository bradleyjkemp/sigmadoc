---
title: "TropicTrooper Campaign November 2018"
aliases:
  - "/rule/8c7090c3-e0a0-4944-bd08-08c3a0cecf79"

tags:
  - attack.execution
  - attack.t1059
  - attack.t1059.001



date: Mon, 3 Dec 2018 09:42:29 +0200


---

Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia

<!--more-->




## References

* https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/


## Raw rule
```yaml
title: TropicTrooper Campaign November 2018
id: 8c7090c3-e0a0-4944-bd08-08c3a0cecf79
author: '@41thexplorer, Microsoft Defender ATP'
status: stable
date: 2019/11/12
modified: 2020/08/27
description: Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia
references:
    - https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/
tags:
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*'
    condition: selection
level: high

```
