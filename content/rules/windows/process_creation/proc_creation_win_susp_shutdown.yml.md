---
title: "Suspicious Execution of Shutdown"
aliases:
  - "/rule/34ebb878-1b15-4895-b352-ca2eeb99b274"


tags:
  - attack.impact
  - attack.t1529



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Use of the commandline to shutdown or reboot windows

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_shutdown.yml))
```yaml
title: Suspicious Execution of Shutdown 
id: 34ebb878-1b15-4895-b352-ca2eeb99b274
status: experimental
description: Use of the commandline to shutdown or reboot windows 
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1529/T1529.md
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \shutdown.exe
        CommandLine|contains: 
            - '/r ' 
            - '/s '
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.impact
    - attack.t1529

```
