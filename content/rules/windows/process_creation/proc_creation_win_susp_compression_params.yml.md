---
title: "Suspicious Compression Tool Parameters"
aliases:
  - "/rule/27a72a60-7e5e-47b1-9d17-909c9abafdcd"
ruleid: 27a72a60-7e5e-47b1-9d17-909c9abafdcd

tags:
  - attack.collection
  - attack.t1560.001



status: test





date: Tue, 15 Oct 2019 16:38:53 +0200


---

Detects suspicious command line arguments of common data compression tools

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1184067445612535811


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_compression_params.yml))
```yaml
title: Suspicious Compression Tool Parameters
id: 27a72a60-7e5e-47b1-9d17-909c9abafdcd
status: test
description: Detects suspicious command line arguments of common data compression tools
author: Florian Roth, Samir Bousseaden
references:
  - https://twitter.com/SBousseaden/status/1184067445612535811
date: 2019/10/15
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    OriginalFileName:
      - '7z*.exe'
      - '*rar.exe'
      - '*Command*Line*RAR*'
    CommandLine|contains:
      - ' -p'
      - ' -ta'
      - ' -tb'
      - ' -sdel'
      - ' -dw'
      - ' -hp'
  falsepositive:
    ParentImage|startswith: 'C:\Program'
  condition: selection and not falsepositive
falsepositives:
  - unknown
level: high
tags:
  - attack.collection
  - attack.t1560.001

```
