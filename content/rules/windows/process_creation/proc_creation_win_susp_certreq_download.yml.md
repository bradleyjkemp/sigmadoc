---
title: "Suspicious Certreq Command to Download"
aliases:
  - "/rule/4480827a-9799-4232-b2c4-ccc6c4e9e12b"
ruleid: 4480827a-9799-4232-b2c4-ccc6c4e9e12b

tags:
  - attack.command_and_control
  - attack.t1105



status: experimental





date: Wed, 24 Nov 2021 16:39:44 +0100


---

Detects a suspicious certreq execution taken from the LOLBAS examples, which can be abused to download (small) files

<!--more-->


## Known false-positives

* Unlikely



## References

* https://lolbas-project.github.io/lolbas/Binaries/Certreq/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_certreq_download.yml))
```yaml
title: Suspicious Certreq Command to Download
id: 4480827a-9799-4232-b2c4-ccc6c4e9e12b
status: experimental
description: Detects a suspicious certreq execution taken from the LOLBAS examples, which can be abused to download (small) files
author: Christian Burkard
date: 2021/11/24
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certreq/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certreq.exe'
        CommandLine|contains|all:
            - ' -Post '
            - ' -config '
            - ' http'
            - ' C:\windows\win.ini '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.command_and_control
    - attack.t1105
falsepositives:
    - Unlikely
level: high

```
