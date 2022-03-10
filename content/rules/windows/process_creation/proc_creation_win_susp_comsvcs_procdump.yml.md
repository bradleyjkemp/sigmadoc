---
title: "Process Dump via Comsvcs DLL"
aliases:
  - "/rule/09e6d5c0-05b8-4ff8-9eeb-043046ec774c"


tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.credential_access
  - attack.t1003.001



status: test





date: Mon, 2 Sep 2019 07:49:19 -0400


---

Detects process memory dump via comsvcs.dll and rundll32

<!--more-->


## Known false-positives

* unknown



## References

* https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
* https://twitter.com/SBousseaden/status/1167417096374050817


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_comsvcs_procdump.yml))
```yaml
title: Process Dump via Comsvcs DLL
id: 09e6d5c0-05b8-4ff8-9eeb-043046ec774c
status: test
description: Detects process memory dump via comsvcs.dll and rundll32
author: Modexp (idea)
references:
  - https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/
  - https://twitter.com/SBousseaden/status/1167417096374050817
date: 2019/09/02
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  rundll_image:
    Image|endswith: '\rundll32.exe'
  rundll_ofn:
    OriginalFileName: 'RUNDLL32.EXE'
  selection:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'MiniDump'       #Matches MiniDump and MinidumpW
      - 'full'
  condition: (rundll_image or rundll_ofn) and selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.credential_access
  - attack.t1003.001

```