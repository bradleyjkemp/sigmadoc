---
title: "Suspicious Dump64.exe Execution"
aliases:
  - "/rule/129966c9-de17-4334-a123-8b58172e664d"


tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Fri, 26 Nov 2021 14:03:10 -0600


---

Detects when a user bypasses Defender by renaming a tool to dump64.exe and placing it in a Visual Studio folder

<!--more-->


## Known false-positives

* Dump64.exe in other folders than the excluded one



## References

* https://twitter.com/mrd0x/status/1460597833917251595


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_win_lolbas_dump64.yml))
```yaml
title: Suspicious Dump64.exe Execution 
id: 129966c9-de17-4334-a123-8b58172e664d
description: Detects when a user bypasses Defender by renaming a tool to dump64.exe and placing it in a Visual Studio folder
status: experimental
author: Austin Songer @austinsonger, Florian Roth
date: 2021/11/26
references:
    - https://twitter.com/mrd0x/status/1460597833917251595
logsource:
      product: windows
      category: process_creation
detection: 
    selection:
        Image|endswith: '\dump64.exe'
    procdump_flags:
        CommandLine|contains:
            - ' -ma '
            - 'accpeteula'
    filter:
        Image|contains: '\Installer\Feedback\dump64.exe'
    condition: ( selection and not filter ) or ( selection and procdump_flags )
tags:
    - attack.credential_access
    - attack.t1003.001
falsepositives:
    - Dump64.exe in other folders than the excluded one
level: high

```
