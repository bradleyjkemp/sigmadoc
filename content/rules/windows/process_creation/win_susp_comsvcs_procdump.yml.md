---
title: "Process Dump via Comsvcs DLL"
aliases:
  - "/rule/09e6d5c0-05b8-4ff8-9eeb-043046ec774c"

tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003



status: experimental



level: medium



date: Mon, 2 Sep 2019 07:49:19 -0400


---

Detects process memory dump via comsvcs.dll and rundll32

<!--more-->


## Known false-positives

* unknown



## References

* https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
* https://twitter.com/SBousseaden/status/1167417096374050817


## Raw rule
```yaml
title: Process Dump via Comsvcs DLL
id: 09e6d5c0-05b8-4ff8-9eeb-043046ec774c
status: experimental
description: Detects process memory dump via comsvcs.dll and rundll32
references:
    - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
    - https://twitter.com/SBousseaden/status/1167417096374050817
author: Modexp (idea)
date: 2019/09/02
modified: 2020/09/05
logsource:
    category: process_creation
    product: windows
detection:
    rundll_image:
        Image: '*\rundll32.exe'
    rundll_ofn:
        OriginalFileName: 'RUNDLL32.EXE'
    selection:
        CommandLine:
            - '*comsvcs*MiniDump*full*'
            - '*comsvcs*MiniDumpW*full*'
    condition: (rundll_image or rundll_ofn) and selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1218.011
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003      # an old one
falsepositives:
    - unknown
level: medium

```
