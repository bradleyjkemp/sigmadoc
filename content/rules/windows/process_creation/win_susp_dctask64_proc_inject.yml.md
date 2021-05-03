---
title: "ZOHO Dctask64 Process Injection"
aliases:
  - "/rule/6345b048-8441-43a7-9bed-541133633d7a"

tags:
  - attack.defense_evasion
  - attack.t1055.001
  - attack.t1055



date: Tue, 28 Jan 2020 11:29:24 +0100


---

Detects suspicious process injection using ZOHO's dctask64.exe

<!--more-->


## Known false-positives

* Unknown yet



## References

* https://twitter.com/gN3mes1s/status/1222088214581825540
* https://twitter.com/gN3mes1s/status/1222095963789111296
* https://twitter.com/gN3mes1s/status/1222095371175911424


## Raw rule
```yaml
title: ZOHO Dctask64 Process Injection
id: 6345b048-8441-43a7-9bed-541133633d7a
status: experimental
description: Detects suspicious process injection using ZOHO's dctask64.exe
references:
    - https://twitter.com/gN3mes1s/status/1222088214581825540
    - https://twitter.com/gN3mes1s/status/1222095963789111296
    - https://twitter.com/gN3mes1s/status/1222095371175911424
author: Florian Roth
date: 2020/01/28
modified: 2020/08/30
tags:
    - attack.defense_evasion
    - attack.t1055.001
    - attack.t1055      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\dctask64.exe'
    filter:
        CommandLine|contains:
            - 'DesktopCentral_Agent\agent'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
    - ParentImage
falsepositives:
    - Unknown yet
level: high

```