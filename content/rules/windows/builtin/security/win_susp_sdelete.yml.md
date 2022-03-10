---
title: "Secure Deletion with SDelete"
aliases:
  - "/rule/39a80702-d7ca-4a83-b776-525b1f86a36d"


tags:
  - attack.impact
  - attack.defense_evasion
  - attack.t1070.004
  - attack.t1027.005
  - attack.t1485
  - attack.t1553.002
  - attack.s0195



status: test





date: Wed, 14 Jun 2017 16:55:32 +0200


---

Detects renaming of file while deletion with SDelete tool.

<!--more-->


## Known false-positives

* Legitimate usage of SDelete



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/sdelete.htm
* https://www.jpcert.or.jp/english/pub/sr/ir_research.html
* https://docs.microsoft.com/en-gb/sysinternals/downloads/sdelete


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_sdelete.yml))
```yaml
title: Secure Deletion with SDelete
id: 39a80702-d7ca-4a83-b776-525b1f86a36d
status: test
description: Detects renaming of file while deletion with SDelete tool.
author: Thomas Patzke
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/sdelete.htm
  - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
  - https://docs.microsoft.com/en-gb/sysinternals/downloads/sdelete
date: 2017/06/14
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4656
      - 4663
      - 4658
    ObjectName|endswith:
      - '.AAA'
      - '.ZZZ'
  condition: selection
falsepositives:
  - Legitimate usage of SDelete
level: medium
tags:
  - attack.impact
  - attack.defense_evasion
  - attack.t1070.004
  - attack.t1027.005
  - attack.t1485
  - attack.t1553.002
  - attack.s0195

```
