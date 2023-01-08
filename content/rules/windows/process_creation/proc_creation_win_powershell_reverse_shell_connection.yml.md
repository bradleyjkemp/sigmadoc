---
title: "Powershell Reverse Shell Connection"
aliases:
  - "/rule/edc2f8ae-2412-4dfd-b9d5-0c57727e70be"
ruleid: edc2f8ae-2412-4dfd-b9d5-0c57727e70be

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the Nishang Invoke-PowerShellTcpOneLine reverse shell

<!--more-->


## Known false-positives

* Administrative might use this function for checking network connectivity



## References

* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
* https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_reverse_shell_connection.yml))
```yaml
title: Powershell Reverse Shell Connection
id: edc2f8ae-2412-4dfd-b9d5-0c57727e70be
status: experimental
description: Detects the Nishang Invoke-PowerShellTcpOneLine reverse shell
author: FPT.EagleEye, wagga
references:
    - https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
    - https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/
date: 2021/03/03
modified: 2021/06/27
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'new-object system.net.sockets.tcpclient'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative might use this function for checking network connectivity
level: high

```
