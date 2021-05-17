---
title: "WCE wceaux.dll Access"
aliases:
  - "/rule/1de68c67-af5c-4097-9c85-fe5578e09e67"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.s0005



status: experimental



level: critical



date: Wed, 14 Jun 2017 15:59:45 +0200


---

Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host

<!--more-->


## Known false-positives

* Penetration testing



## References

* https://www.jpcert.or.jp/english/pub/sr/ir_research.html
* https://jpcertcc.github.io/ToolAnalysisResultSheet


## Raw rule
```yaml
title: WCE wceaux.dll Access
id: 1de68c67-af5c-4097-9c85-fe5578e09e67
status: experimental
description: Detects wceaux.dll access while WCE pass-the-hash remote command execution on source host
author: Thomas Patzke
date: 2017/06/14
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4658
            - 4660
            - 4663
        ObjectName: '*\wceaux.dll'
    condition: selection
falsepositives:
    - Penetration testing
level: critical

```
