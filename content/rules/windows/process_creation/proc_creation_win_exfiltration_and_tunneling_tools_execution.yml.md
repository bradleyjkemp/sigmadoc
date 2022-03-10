---
title: "Exfiltration and Tunneling Tools Execution"
aliases:
  - "/rule/c75309a3-59f8-4a8d-9c2c-4c927ad50555"


tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.t1041
  - attack.t1572
  - attack.t1071.001



status: test





date: Fri, 25 Oct 2019 04:30:55 +0200


---

Execution of well known tools for data exfiltration and tunneling

<!--more-->


## Known false-positives

* Legitimate Administrator using tools




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_exfiltration_and_tunneling_tools_execution.yml))
```yaml
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
status: test
description: Execution of well known tools for data exfiltration and tunneling
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\plink.exe'
      - '\socat.exe'
      - '\stunnel.exe'
      - '\httptunnel.exe'
  condition: selection
falsepositives:
  - Legitimate Administrator using tools
level: medium
tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.t1041
  - attack.t1572
  - attack.t1071.001

```
