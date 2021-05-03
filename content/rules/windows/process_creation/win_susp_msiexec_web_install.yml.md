---
title: "MsiExec Web Install"
aliases:
  - "/rule/f7b5f842-a6af-4da5-9e95-e32478f3cd2f"

tags:
  - attack.defense_evasion
  - attack.t1218.007
  - attack.command_and_control
  - attack.t1105



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious msiexec process starts with web addreses as parameter

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/


## Raw rule
```yaml
title: MsiExec Web Install
id: f7b5f842-a6af-4da5-9e95-e32478f3cd2f
status: experimental
description: Detects suspicious msiexec process starts with web addreses as parameter
references:
    - https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/
tags:
    - attack.defense_evasion
    - attack.t1218.007
    - attack.command_and_control
    - attack.t1105
author: Florian Roth
date: 2018/02/09
modified: 2020/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* msiexec*://*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```
