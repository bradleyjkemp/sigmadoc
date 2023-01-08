---
title: "Monitoring Winget For LOLbin Execution"
aliases:
  - "/rule/313d6012-51a0-4d93-8dfc-de8553239e25"
ruleid: 313d6012-51a0-4d93-8dfc-de8553239e25

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries can abuse winget to download payloads remotely and execute them without touching disk. Winget will be included by default in Windows 10 and is already available in Windows 10 insider programs. The manifest option enables you to install an application by passing in a YAML file directly to the client. Winget can be used to download and install exe's, msi, msix files later.

<!--more-->


## Known false-positives

* Admin activity installing packages not in the official Microsoft repo. Winget probably won't be used by most users.



## References

* https://docs.microsoft.com/en-us/windows/package-manager/winget/install#local-install


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbin_execution_via_winget.yml))
```yaml
title: Monitoring Winget For LOLbin Execution
id: 313d6012-51a0-4d93-8dfc-de8553239e25
description: Adversaries can abuse winget to download payloads remotely and execute them without touching disk. Winget will be included by default in Windows 10 and is already available in Windows 10 insider programs. The manifest option enables you to install an application by passing in a YAML file directly to the client. Winget can be used to download and install exe's, msi, msix files later.
status: experimental
references: 
    - https://docs.microsoft.com/en-us/windows/package-manager/winget/install#local-install
author: Sreeman, Florian Roth, Frack113
date: 2020/04/21
modified: 2022/01/11
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'winget'
            - 'install'
        CommandLine|contains:
            - '-m '
            - '--manifest'
    condition: selection
falsepositives:
    - Admin activity installing packages not in the official Microsoft repo. Winget probably won't be used by most users.
fields:
    - CommandLine
level: medium

```
