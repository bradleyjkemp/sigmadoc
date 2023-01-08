---
title: "Suspicious LOLBIN AccCheckConsole"
aliases:
  - "/rule/0f6da907-5854-4be6-859a-e9958747b0aa"
ruleid: 0f6da907-5854-4be6-859a-e9958747b0aa

tags:
  - attack.execution



status: experimental





date: Thu, 6 Jan 2022 17:23:41 +0100


---

Detects suspicious LOLBIN AccCheckConsole execution with parameters as used to load an arbitrary DLL

<!--more-->


## Known false-positives

* Legitimate use of the UI Accessibility Checker



## References

* https://gist.github.com/bohops/2444129419c8acf837aedda5f0e7f340
* https://twitter.com/bohops/status/1477717351017680899?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_acccheckconsole.yml))
```yaml
title: Suspicious LOLBIN AccCheckConsole
id: 0f6da907-5854-4be6-859a-e9958747b0aa
status: experimental
description: Detects suspicious LOLBIN AccCheckConsole execution with parameters as used to load an arbitrary DLL
references:
    - https://gist.github.com/bohops/2444129419c8acf837aedda5f0e7f340
    - https://twitter.com/bohops/status/1477717351017680899?s=12
author: Florian Roth
date: 2022/01/06
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\AccCheckConsole.exe'
        CommandLine|contains|all:
            - ' -window '
            - '.dll'
    condition: selection
falsepositives:
    - Legitimate use of the UI Accessibility Checker
level: high
```
