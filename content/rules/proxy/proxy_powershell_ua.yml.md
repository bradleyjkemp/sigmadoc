---
title: "Windows PowerShell User Agent"
aliases:
  - "/rule/c8557060-9221-4448-8794-96320e6f3e74"

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



date: Mon, 13 Mar 2017 13:51:32 +0100


---

Detects Windows PowerShell Web Access

<!--more-->


## Known false-positives

* Administrative scripts that download files from the Internet
* Administrative scripts that retrieve certain website contents



## References

* https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest


## Raw rule
```yaml
title: Windows PowerShell User Agent
id: c8557060-9221-4448-8794-96320e6f3e74
status: experimental
description: Detects Windows PowerShell Web Access
author: Florian Roth
date: 2017/03/13
modified: 2020/09/03
references:
    - https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
logsource:
    category: proxy
detection:
    selection:
      c-useragent: '* WindowsPowerShell/*'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Administrative scripts that download files from the Internet
    - Administrative scripts that retrieve certain website contents
level: medium
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
```
