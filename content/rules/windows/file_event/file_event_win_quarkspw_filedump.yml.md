---
title: "QuarksPwDump Dump File"
aliases:
  - "/rule/847def9e-924d-4e90-b7c4-5f581395a2b4"


tags:
  - attack.credential_access
  - attack.t1003.002



status: test





date: Sat, 10 Feb 2018 15:25:36 +0100


---

Detects a dump file written by QuarksPwDump password dumper

<!--more-->


## Known false-positives

* Unknown



## References

* https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_quarkspw_filedump.yml))
```yaml
title: QuarksPwDump Dump File
id: 847def9e-924d-4e90-b7c4-5f581395a2b4
status: test
description: Detects a dump file written by QuarksPwDump password dumper
author: Florian Roth
references:
  - https://jpcertcc.github.io/ToolAnalysisResultSheet/details/QuarksPWDump.htm
date: 2018/02/10
modified: 2021/11/27
logsource:
  category: file_event
  product: windows
detection:
  selection:
        # Sysmon: File Creation (ID 11)
    TargetFilename|contains|all:
      - '\AppData\Local\Temp\SAM-'
      - '.dmp'
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.credential_access
  - attack.t1003.002

```
