---
title: "Suspicious Log Entries"
aliases:
  - "/rule/f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1"



status: experimental



level: medium



date: Sat, 25 Mar 2017 19:59:45 +0100


---

Detects suspicious log entries in Linux log files

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: Suspicious Log Entries
id: f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1
status: experimental
description: Detects suspicious log entries in Linux log files
author: Florian Roth
date: 2017/03/25
logsource:
    product: linux
detection:
    keywords:
        - entered promiscuous mode
        - Deactivating service
        - Oversized packet received from
        - imuxsock begins to drop messages
    condition: keywords
falsepositives:
    - Unknown
level: medium

```
