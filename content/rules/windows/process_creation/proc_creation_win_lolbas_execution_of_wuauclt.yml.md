---
title: "Monitoring Wuauclt.exe For Lolbas Execution Of DLL"
aliases:
  - "/rule/ba1bb0cb-73da-42de-ad3a-de10c643a5d0"


tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1218.011



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries can abuse wuauclt.exe (Windows Update client) to run code execution by specifying an arbitrary DLL.

<!--more-->


## Known false-positives

* Wuaueng.dll which is a module belonging to Microsoft Windows Update.



## References

* https://dtm.uk/wuauclt/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_execution_of_wuauclt.yml))
```yaml
title: Monitoring Wuauclt.exe For Lolbas Execution Of DLL
id: ba1bb0cb-73da-42de-ad3a-de10c643a5d0
status: experimental
description: Adversaries can abuse wuauclt.exe (Windows Update client) to run code execution by specifying an arbitrary DLL.
references:
    - https://dtm.uk/wuauclt/
author: Sreeman
date: 2020/10/29
modified: 2022/03/07
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains|all:
            - 'wuauclt.exe'
            - '/UpdateDeploymentProvider'
            - '/Runhandlercomserver'
    filter:
        CommandLine|contains:
            - 'wuaueng.dll'
            - 'UpdateDeploymentProvider.dll /ClassId'
    condition: selection and not filter
falsepositives:
    - Wuaueng.dll which is a module belonging to Microsoft Windows Update.
fields:
    - CommandLine
level: medium
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218.011

```
