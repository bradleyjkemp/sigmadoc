---
title: "Script Event Consumer Spawning Process"
aliases:
  - "/rule/f6d1dd2f-b8ce-40ca-bc23-062efb686b34"
ruleid: f6d1dd2f-b8ce-40ca-bc23-062efb686b34

tags:
  - attack.execution
  - attack.t1047



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a suspicious child process of Script Event Consumer (scrcons.exe).

<!--more-->


## Known false-positives

* unknown



## References

* https://redcanary.com/blog/child-processes/
* https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_script_event_consumer_spawn.yml))
```yaml
title: Script Event Consumer Spawning Process
id: f6d1dd2f-b8ce-40ca-bc23-062efb686b34
status: experimental
description: Detects a suspicious child process of Script Event Consumer (scrcons.exe).
references:
    - https://redcanary.com/blog/child-processes/
    - https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-analytics-alert-reference/cortex-xdr-analytics-alert-reference/scrcons-exe-rare-child-process.html
author: Sittikorn S
date: 2021/06/21
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\scrcons.exe'
        Image|endswith:
            - '\svchost.exe'
            - '\dllhost.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\msbuild.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```
