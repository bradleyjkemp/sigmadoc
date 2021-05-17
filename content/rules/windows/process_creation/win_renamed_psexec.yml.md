---
title: "Renamed PsExec"
aliases:
  - "/rule/a7a7e0e5-1d57-49df-9c58-9fe5bc0346a2"

tags:
  - car.2013-05-009
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.003



status: experimental



level: high



date: Tue, 21 May 2019 09:49:34 +0200


---

Detects the execution of a renamed PsExec often used by attackers or malware

<!--more-->


## Known false-positives

* Software that illegaly integrates PsExec in a renamed form
* Administrators that have renamed PsExec and no one knows why



## References

* https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks


## Raw rule
```yaml
title: Renamed PsExec
id: a7a7e0e5-1d57-49df-9c58-9fe5bc0346a2
status: experimental
description: Detects the execution of a renamed PsExec often used by attackers or malware
references:
    - https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/megacortex-ransomware-spotted-attacking-enterprise-networks
author: Florian Roth
date: 2019/05/21
modified: 2020/09/06
tags:
    - car.2013-05-009
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Description: 'Execute processes remotely'
        Product: 'Sysinternals PsExec'
    filter:
        Image:
           - '*\PsExec.exe'
           - '*\PsExec64.exe'
    condition: selection and not filter
falsepositives:
    - Software that illegaly integrates PsExec in a renamed form
    - Administrators that have renamed PsExec and no one knows why
level: high

```
