---
title: "Windows Suspicious Use Of Web Request in CommandLine"
aliases:
  - "/rule/9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d"
ruleid: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 24 Oct 2019 11:57:37 +1100


---

Detects the use of various web request with commandline tools or Windows PowerShell command,methods (including aliases)

<!--more-->


## Known false-positives

* Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.



## References

* https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
* https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_web_request_cmd.yml))
```yaml
title: Windows Suspicious Use Of Web Request in CommandLine
id: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
status: experimental
description: Detects the use of various web request with commandline tools or Windows PowerShell command,methods (including aliases)
references:
    - https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
    - https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
author: James Pemberton / @4A616D6573
date: 2019/10/24
modified: 2021/09/21
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
    condition: selection
falsepositives:
    - Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.
level: medium
```
