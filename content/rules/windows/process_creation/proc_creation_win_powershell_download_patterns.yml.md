---
title: "Suspicious PowerShell Download and Execute Pattern"
aliases:
  - "/rule/e6c54d94-498c-4562-a37c-b469d8e9a275"
ruleid: e6c54d94-498c-4562-a37c-b469d8e9a275

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Mon, 28 Feb 2022 14:42:56 +0100


---

Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)

<!--more-->


## Known false-positives

* Software installers that pull packages from remote systems and execute them



## References

* https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_download_patterns.yml))
```yaml
title: Suspicious PowerShell Download and Execute Pattern
id: e6c54d94-498c-4562-a37c-b469d8e9a275
status: experimental
description: Detects suspicious PowerShell download patterns that are often used in malicious scripts, stagers or downloaders (make sure that your backend applies the strings case-insensitive)
author: Florian Roth
references:
   - https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70
date: 2022/02/28
modified: 2022/03/01
logsource:
   category: process_creation
   product: windows
detection:
   selection:
      CommandLine|contains:  # make sure that your backend applies the strings case-insensitive
         - 'IEX ((New-Object Net.WebClient).DownloadString'
         - 'IEX (New-Object Net.WebClient).DownloadString'
         - 'IEX((New-Object Net.WebClient).DownloadString'
         - 'IEX(New-Object Net.WebClient).DownloadString'
         - ' -command (New-Object System.Net.WebClient).DownloadFile('
         - ' -c (New-Object System.Net.WebClient).DownloadFile('
   condition: selection
falsepositives:
   - Software installers that pull packages from remote systems and execute them
level: high
tags:
   - attack.execution
   - attack.t1059.001

```