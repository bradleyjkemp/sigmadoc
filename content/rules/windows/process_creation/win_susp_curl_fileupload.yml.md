---
title: "Suspicious Curl File Upload"
aliases:
  - "/rule/00bca14a-df4e-4649-9054-3f2aa676bc04"

tags:
  - attack.exfiltration
  - attack.t1567



date: Fri, 3 Jul 2020 18:20:44 +0200


---

Detects a suspicious curl process start the adds a file to a web request

<!--more-->


## Known false-positives

* Scripts created by developers and admins



## References

* https://twitter.com/d1r4c/status/1279042657508081664
* https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76


## Raw rule
```yaml
title: Suspicious Curl File Upload
id: 00bca14a-df4e-4649-9054-3f2aa676bc04
status: experimental
description: Detects a suspicious curl process start the adds a file to a web request
author: Florian Roth
date: 2020/07/03
modified: 2020/09/05
references:
    - https://twitter.com/d1r4c/status/1279042657508081664
    - https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
logsource:
    category: process_creation
    product: windows
tags:
    - attack.exfiltration
    - attack.t1567
detection:
    selection:
        Image|endswith: '\curl.exe'
        CommandLine|contains: ' -F '
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Scripts created by developers and admins
level: medium

```