---
title: "Suspicious WMI Execution Using Rundll32"
aliases:
  - "/rule/3c89a1e8-0fba-449e-8f1b-8409d6267ec8"


tags:
  - attack.execution
  - attack.t1047



status: test





date: Mon, 12 Oct 2020 09:18:30 +0200


---

Detects WMI executing rundll32

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2020/10/08/ryuks-return/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_wmic_proc_create_rundll32.yml))
```yaml
title: Suspicious WMI Execution Using Rundll32
id: 3c89a1e8-0fba-449e-8f1b-8409d6267ec8
status: test
description: Detects WMI executing rundll32
author: Florian Roth
references:
  - https://thedfirreport.com/2020/10/08/ryuks-return/
date: 2020/10/12
modified: 2021/11/27
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
falsepositives:
  - Unknown
level: high
tags:
  - attack.execution
  - attack.t1047

```
