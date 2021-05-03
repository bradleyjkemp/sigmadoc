---
title: "Secure Deletion with SDelete"
aliases:
  - "/rule/39a80702-d7ca-4a83-b776-525b1f86a36d"

tags:
  - attack.impact
  - attack.defense_evasion
  - attack.t1107
  - attack.t1070.004
  - attack.t1066
  - attack.t1027.005
  - attack.t1485
  - attack.t1553.002
  - attack.s0195



date: Wed, 14 Jun 2017 16:55:32 +0200


---

Detects renaming of file while deletion with SDelete tool

<!--more-->


## Known false-positives

* Legitime usage of SDelete



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet
* https://www.jpcert.or.jp/english/pub/sr/ir_research.html
* https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx


## Raw rule
```yaml
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: experimental
description: Detects renaming of file while deletion with SDelete tool
author: Thomas Patzke
date: 2017/06/14
modified: 2020/08/2
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://technet.microsoft.com/en-us/en-en/sysinternals/sdelete.aspx
tags:
    - attack.impact
    - attack.defense_evasion
    - attack.t1107           # an old one
    - attack.t1070.004
    - attack.t1066           # an old one
    - attack.t1027.005
    - attack.t1485
    - attack.t1553.002
    - attack.s0195
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
            - 4658
        ObjectName:
            - '*.AAA'
            - '*.ZZZ'
    condition: selection
falsepositives:
    - Legitime usage of SDelete
level: medium

```