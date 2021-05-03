---
title: "WMIExec VBS Script"
aliases:
  - "/rule/966e4016-627f-44f7-8341-f394905c361f"

tags:
  - attack.execution
  - attack.g0045
  - attack.t1064
  - attack.t1059.005



date: Fri, 7 Apr 2017 17:41:53 +0200


---

Detects suspicious file execution by wscript and cscript

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf


## Raw rule
```yaml
title: WMIExec VBS Script
id: 966e4016-627f-44f7-8341-f394905c361f
description: Detects suspicious file execution by wscript and cscript
author: Florian Roth
date: 2017/04/07
references:
    - https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
tags:
    - attack.execution
    - attack.g0045
    - attack.t1064 # an old one
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cscript.exe'
        CommandLine: '*.vbs /shell *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: critical

```
