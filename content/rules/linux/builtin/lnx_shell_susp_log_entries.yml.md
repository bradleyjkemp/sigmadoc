---
title: "Suspicious Log Entries"
aliases:
  - "/rule/f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1"
ruleid: f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1

tags:
  - attack.impact



status: test





date: Sat, 25 Mar 2017 19:59:45 +0100


---

Detects suspicious log entries in Linux log files

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_shell_susp_log_entries.yml))
```yaml
title: Suspicious Log Entries
id: f64b6e9a-5d9d-48a5-8289-e1dd2b3876e1
status: test
description: Detects suspicious log entries in Linux log files
author: Florian Roth
date: 2017/03/25
modified: 2021/11/27
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
tags:
  - attack.impact

```
