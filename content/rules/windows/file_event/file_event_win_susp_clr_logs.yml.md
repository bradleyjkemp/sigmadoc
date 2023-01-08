---
title: "Suspcious CLR Logs Creation"
aliases:
  - "/rule/e4b63079-6198-405c-abd7-3fe8b0ce3263"
ruleid: e4b63079-6198-405c-abd7-3fe8b0ce3263

tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1059.001
  - attack.t1218



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious .NET assembly executions. Could detect using Cobalt Strike's command execute-assembly.

<!--more-->


## Known false-positives

* https://twitter.com/SBousseaden/status/1388064061087260675 - rundll32.exe with zzzzInvokeManagedCustomActionOutOfProc in command line and msiexec.exe as parent process



## References

* https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
* https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
* https://github.com/olafhartong/sysmon-modular/blob/master/11_file_create/include_dotnet.xml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_clr_logs.yml))
```yaml
title: Suspcious CLR Logs Creation
id: e4b63079-6198-405c-abd7-3fe8b0ce3263
description: Detects suspicious .NET assembly executions. Could detect using Cobalt Strike's command execute-assembly. 
references:
    - https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
    - https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
    - https://github.com/olafhartong/sysmon-modular/blob/master/11_file_create/include_dotnet.xml
date: 2020/10/12
modified: 2021/11/17
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059.001
    - attack.t1218
status: experimental
author: omkar72, oscd.community, Wojciech Lesicki
logsource:
    category: file_event
    product: windows
    definition: Check your sysmon configuration for monitoring UsageLogs folder. In SwiftOnSecurity configuration we have that thanks @SBousseaden
detection:
    selection:
        TargetFilename|contains|all:
          - '\AppData\Local\Microsoft\CLR'
          - '\UsageLogs\'
        TargetFilename|contains:
          - 'mshta'
          - 'cscript'
          - 'wscript'
          - 'regsvr32'
          - 'wmic'
          - 'rundll32'
          - 'svchost'
    condition: selection
falsepositives:
  - https://twitter.com/SBousseaden/status/1388064061087260675 - rundll32.exe with zzzzInvokeManagedCustomActionOutOfProc in command line and msiexec.exe as parent process
level: high

```
