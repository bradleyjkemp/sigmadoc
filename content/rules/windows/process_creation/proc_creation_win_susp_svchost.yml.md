---
title: "Suspicious Svchost Process"
aliases:
  - "/rule/01d2e2a1-5f09-44f7-9fc1-24faa7479b6d"


tags:
  - attack.defense_evasion
  - attack.t1036.005



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious svchost process start

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_svchost.yml))
```yaml
title: Suspicious Svchost Process
id: 01d2e2a1-5f09-44f7-9fc1-24faa7479b6d
status: experimental
description: Detects a suspicious svchost process start
tags:
    - attack.defense_evasion
    - attack.t1036.005
author: Florian Roth
date: 2017/08/15
modified: 2022/02/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\svchost.exe'
    filter:
        ParentImage|endswith:
            - '\services.exe'
            - '\MsMpEng.exe'
            - '\Mrt.exe'
            - '\rpcnet.exe'
            - '\svchost.exe'
            - '\ngen.exe'
            - '\TiWorker.exe'
    filter_null1:
        ParentImage: null
    filter_null2:
        ParentImage: ''
    filter_emptysysmon:
        ParentImage: '-'
    condition: selection and not 1 of filter*
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
