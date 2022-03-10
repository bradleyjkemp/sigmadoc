---
title: "UNC2452 PowerShell Pattern"
aliases:
  - "/rule/b7155193-8a81-4d8f-805d-88de864ca50c"


tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1047



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports

<!--more-->


## Known false-positives

* Unknown, unlikely, but possible



## References

* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware
* https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md#atomic-test-7---create-a-process-using-wmi-query-and-an-encoded-command


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_unc2452_ps.yml))
```yaml
title: UNC2452 PowerShell Pattern
id: b7155193-8a81-4d8f-805d-88de864ca50c
description: Detects a specific PowerShell command line pattern used by the UNC2452 actors as mentioned in Microsoft and Symantec reports
status: experimental
references:
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware
    - https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md#atomic-test-7---create-a-process-using-wmi-query-and-an-encoded-command
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1047
    # - sunburst
author: Florian Roth
date: 2021/01/20
modified: 2021/01/22
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all: 
            - 'Invoke-WMIMethod win32_process -name create -argumentlist'
            - 'rundll32 c:\windows'
    selection2:
         CommandLine|contains|all: 
            - 'wmic /node:'
            - 'process call create "rundll32 c:\windows'   
    condition: selection1 or selection2
falsepositives:
    - Unknown, unlikely, but possible
level: critical
```
