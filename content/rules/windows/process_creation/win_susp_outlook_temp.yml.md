---
title: "Execution in Outlook Temp Folder"
aliases:
  - "/rule/a018fdc3-46a3-44e5-9afb-2cd4af1d4b39"

tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.t1193



status: experimental



level: high



date: Tue, 1 Oct 2019 16:07:43 +0200


---

Detects a suspicious program execution in Outlook temp folder

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: Execution in Outlook Temp Folder
id: a018fdc3-46a3-44e5-9afb-2cd4af1d4b39
status: experimental
description: Detects a suspicious program execution in Outlook temp folder
author: Florian Roth
date: 2019/10/01
tags:
    - attack.initial_access
    - attack.t1566.001
    - attack.t1193      #an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Temporary Internet Files\Content.Outlook\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
