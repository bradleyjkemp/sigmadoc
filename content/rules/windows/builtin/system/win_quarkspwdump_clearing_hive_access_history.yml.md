---
title: "QuarksPwDump Clearing Access History"
aliases:
  - "/rule/39f919f3-980b-4e6f-a975-8af7e507ef2b"
ruleid: 39f919f3-980b-4e6f-a975-8af7e507ef2b

tags:
  - attack.credential_access
  - attack.t1003.002



status: test





date: Mon, 4 Nov 2019 05:05:57 +0300


---

Detects QuarksPwDump clearing access history in hive

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_quarkspwdump_clearing_hive_access_history.yml))
```yaml
title: QuarksPwDump Clearing Access History
id: 39f919f3-980b-4e6f-a975-8af7e507ef2b
status: test
description: Detects QuarksPwDump clearing access history in hive
author: Florian Roth
date: 2017/05/15
modified: 2021/11/27
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
level: critical
tags:
  - attack.credential_access
  - attack.t1003.002

```
