---
title: "WMIExec VBS Script"
aliases:
  - "/rule/966e4016-627f-44f7-8341-f394905c361f"
ruleid: 966e4016-627f-44f7-8341-f394905c361f

tags:
  - attack.execution
  - attack.g0045
  - attack.t1059.005



status: test





date: Fri, 7 Apr 2017 17:41:53 +0200


---

Detects suspicious file execution by wscript and cscript

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_cloudhopper.yml))
```yaml
title: WMIExec VBS Script
id: 966e4016-627f-44f7-8341-f394905c361f
status: test
description: Detects suspicious file execution by wscript and cscript
author: Florian Roth
references:
  - https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
date: 2017/04/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\cscript.exe'
    CommandLine|contains|all:
      - '.vbs'
      - '/shell'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Unlikely
level: critical
tags:
  - attack.execution
  - attack.g0045
  - attack.t1059.005

```
