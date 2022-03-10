---
title: "Malicious PE Execution by Microsoft Visual Studio Debugger"
aliases:
  - "/rule/15c7904e-6ad1-4a45-9b46-5fb25df37fd2"


tags:
  - attack.t1218
  - attack.defense_evasion



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

There is an option for a MS VS Just-In-Time Debugger "vsjitdebugger.exe" to launch specified executable and attach a debugger. This option may be used adversaries to execute malicious code by signed verified binary. The debugger is installed alongside with Microsoft Visual Studio package.

<!--more-->


## Known false-positives

* the process spawned by vsjitdebugger.exe is uncommon.



## References

* https://twitter.com/pabraeken/status/990758590020452353
* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Vsjitdebugger.yml
* https://docs.microsoft.com/en-us/visualstudio/debugger/debug-using-the-just-in-time-debugger?view=vs-2019


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_use_of_vsjitdebugger_bin.yml))
```yaml
title: Malicious PE Execution by Microsoft Visual Studio Debugger
id: 15c7904e-6ad1-4a45-9b46-5fb25df37fd2
status: experimental
description: There is an option for a MS VS Just-In-Time Debugger "vsjitdebugger.exe" to launch specified executable and attach a debugger. This option may be used adversaries to execute malicious code by signed verified binary. The debugger is installed alongside with Microsoft Visual Studio package.
references:
  - https://twitter.com/pabraeken/status/990758590020452353
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Vsjitdebugger.yml
  - https://docs.microsoft.com/en-us/visualstudio/debugger/debug-using-the-just-in-time-debugger?view=vs-2019
tags:
    - attack.t1218
    - attack.defense_evasion
author: Agro (@agro_sev), Ensar Şamil (@sblmsrsn), oscd.community
date: 2020/10/14
modified: 2021/07/06
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vsjitdebugger.exe'
    reduction1:
        Image|endswith: '\vsimmersiveactivatehelper*.exe'
    reduction2:
        Image|endswith: '\devenv.exe'
    condition: selection and not (reduction1 or reduction2)
falsepositives:
    - the process spawned by vsjitdebugger.exe is uncommon.
level: medium


```
