---
title: "QuarksPwDump Clearing Access History"
aliases:
  - "/rule/39f919f3-980b-4e6f-a975-8af7e507ef2b"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002



date: Mon, 4 Nov 2019 05:05:57 +0300


---

Detects QuarksPwDump clearing access history in hive

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: QuarksPwDump Clearing Access History
id: 39f919f3-980b-4e6f-a975-8af7e507ef2b
status: experimental
description: Detects QuarksPwDump clearing access history in hive
author: Florian Roth
date: 2017/05/15
modified: 2019/11/13
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.002
level: critical
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 16
        HiveName|contains: '\AppData\Local\Temp\SAM'
        HiveName|endswith: '.dmp'
    condition: selection
falsepositives:
    - Unknown

```