---
title: "ScreenConnect Remote Access"
aliases:
  - "/rule/75bfe6e6-cd8e-429e-91d3-03921e1d7962"
ruleid: 75bfe6e6-cd8e-429e-91d3-03921e1d7962

tags:
  - attack.initial_access
  - attack.t1133



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)

<!--more-->


## Known false-positives

* Legitimate use by administrative staff



## References

* https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_screenconnect_access.yml))
```yaml
title: ScreenConnect Remote Access
id: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
status: experimental
description: Detects ScreenConnect program starts that establish a remote access to that system (not meeting, not remote support)
references:
    - https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies
author: Florian Roth 
date: 2021/02/11
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'e=Access&'
            - 'y=Guest&'
            - '&p='
            - '&c='
            - '&k='
    condition: selection
falsepositives:
    - Legitimate use by administrative staff
level: high
tags:
    - attack.initial_access 
    - attack.t1133 
```
