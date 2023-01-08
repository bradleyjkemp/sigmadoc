---
title: "Suspicious Script Execution From Temp Folder"
aliases:
  - "/rule/a6a39bdb-935c-4f0a-ab77-35f4bbf44d33"
ruleid: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33

tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Wed, 14 Jul 2021 15:52:52 +0200


---

Detects a suspicious script executions from temporary folder

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_script_exec_from_temp.yml))
```yaml
title: Suspicious Script Execution From Temp Folder
id: a6a39bdb-935c-4f0a-ab77-35f4bbf44d33
description: Detects a suspicious script executions from temporary folder
status: experimental
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
author: Florian Roth, Max Altgelt
date: 2021/07/14
modified: 2021/11/11
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains: 
            - '\Windows\Temp'
            - '\Temporary Internet'
            - '\AppData\Local\Temp'
            - '\AppData\Roaming\Temp'
            - '%TEMP%'
            - '%TMP%'
            - '%LocalAppData%\Temp'
    filter:
        CommandLine|contains: 
            - ' >'
            - 'Out-File'
            - 'ConvertTo-Json'
            - '-WindowStyle hidden -Verb runAs'  # VSCode behaviour if file cannot be written as current user
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: high

```
