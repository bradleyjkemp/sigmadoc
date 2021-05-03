---
title: "Suspicious WMI Execution Using Rundll32"
aliases:
  - "/rule/3c89a1e8-0fba-449e-8f1b-8409d6267ec8"

tags:
  - attack.execution
  - attack.t1047



date: Mon, 12 Oct 2020 09:18:30 +0200


---

Detects WMI executing rundll32

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2020/10/08/ryuks-return/


## Raw rule
```yaml
title: Suspicious WMI Execution Using Rundll32
id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
status: experimental
description: Detects WMI executing rundll32
references:
    - https://thedfirreport.com/2020/10/08/ryuks-return/
author: Florian Roth
date: 2020/10/12
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'process call create'
            - 'rundll32'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.t1047
falsepositives:
    - Unknown
level: high

```
