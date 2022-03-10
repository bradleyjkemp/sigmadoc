---
title: "SAM Dump to AppData"
aliases:
  - "/rule/839dd1e8-eda8-4834-8145-01beeee33acd"


tags:
  - attack.credential_access
  - attack.t1003.002



status: test





date: Mon, 27 Mar 2017 15:20:50 +0200


---

Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers

<!--more-->


## Known false-positives

* Penetration testing




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_susp_sam_dump.yml))
```yaml
title: SAM Dump to AppData
id: 839dd1e8-eda8-4834-8145-01beeee33acd
status: test
description: Detects suspicious SAM dump activity as cause by QuarksPwDump and other password dumpers
author: Florian Roth
date: 2018/01/27
modified: 2021/11/27
logsource:
  product: windows
  service: system
  definition: The source of this type of event is Kernel-General
detection:
  selection:
    EventID: 16
  keywords:
    - '\AppData\Local\Temp\SAM-'
    - '.dmp'
  condition: selection and all of keywords
falsepositives:
  - Penetration testing
level: high
tags:
  - attack.credential_access
  - attack.t1003.002

```
