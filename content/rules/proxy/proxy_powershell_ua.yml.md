---
title: "Windows PowerShell User Agent"
aliases:
  - "/rule/c8557060-9221-4448-8794-96320e6f3e74"


tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Mon, 13 Mar 2017 13:51:32 +0100


---

Detects Windows PowerShell Web Access

<!--more-->


## Known false-positives

* Administrative scripts that download files from the Internet
* Administrative scripts that retrieve certain website contents



## References

* https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_powershell_ua.yml))
```yaml
title: Windows PowerShell User Agent
id: c8557060-9221-4448-8794-96320e6f3e74
status: test
description: Detects Windows PowerShell Web Access
author: Florian Roth
references:
  - https://msdn.microsoft.com/powershell/reference/5.1/microsoft.powershell.utility/Invoke-WebRequest
date: 2017/03/13
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-useragent|contains: ' WindowsPowerShell/'
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
