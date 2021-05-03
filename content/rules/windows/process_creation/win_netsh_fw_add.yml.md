---
title: "Netsh Port or Application Allowed"
aliases:
  - "/rule/cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c"

tags:
  - attack.defense_evasion
  - attack.t1089
  - attack.t1562.004



date: Mon, 1 Apr 2019 08:16:56 +0200


---

Allow Incoming Connections by Port or Application on Windows Firewall

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf


## Raw rule
```yaml
title: Netsh Port or Application Allowed
id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
modified: 2020/09/01
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.004
status: experimental
author: Markus Neis, Sander Wiebing
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*netsh*'
    selection2:
        CommandLine:
            - '*firewall add*'
    condition: selection1 and selection2
falsepositives:
    - Legitimate administration
level: medium

```
