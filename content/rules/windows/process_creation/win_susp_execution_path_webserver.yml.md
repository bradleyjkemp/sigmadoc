---
title: "Execution in Webserver Root Folder"
aliases:
  - "/rule/35efb964-e6a5-47ad-bbcd-19661854018d"

tags:
  - attack.persistence
  - attack.t1505.003
  - attack.t1100



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious program execution in a web service root folder (filter out false positives)

<!--more-->


## Known false-positives

* Various applications
* Tools that include ping or nslookup command invocations




## Raw rule
```yaml
title: Execution in Webserver Root Folder
id: 35efb964-e6a5-47ad-bbcd-19661854018d
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
date: 2019/01/16
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.t1100      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wwwroot\\*'
            - '*\wmpub\\*'
            - '*\htdocs\\*'
    filter:
        Image:
            - '*bin\\*'
            - '*\Tools\\*'
            - '*\SMSComponent\\*'
        ParentImage:
            - '*\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```
