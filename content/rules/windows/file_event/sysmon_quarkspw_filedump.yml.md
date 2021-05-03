---
title: "QuarksPwDump Dump File"
aliases:
  - "/rule/847def9e-924d-4e90-b7c4-5f581395a2b4"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002



date: Sat, 10 Feb 2018 15:25:36 +0100


---

Detects a dump file written by QuarksPwDump password dumper

<!--more-->


## Known false-positives

* Unknown



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm


## Raw rule
```yaml
title: QuarksPwDump Dump File
id: 847def9e-924d-4e90-b7c4-5f581395a2b4
status: experimental
description: Detects a dump file written by QuarksPwDump password dumper
references:
    - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm
author: Florian Roth
date: 2018/02/10
modified: 2020/08/23
tags:
  - attack.credential_access
  - attack.t1003          # an old one
  - attack.t1003.002
level: critical
logsource:
    category: file_event
    product: windows
detection:
    selection:
        # Sysmon: File Creation (ID 11)
        TargetFilename: '*\AppData\Local\Temp\SAM-*.dmp*'
    condition: selection
falsepositives:
    - Unknown

```
