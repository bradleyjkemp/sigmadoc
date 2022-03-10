---
title: "Suspicious Driver Install by pnputil.exe"
aliases:
  - "/rule/a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1"


tags:
  - attack.persistence
  - attack.t1547
  - attack.t1547.006



status: experimental





date: Thu, 30 Sep 2021 19:14:34 -0500


---

Detects when a possible suspicious driver is being installed via pnputil.exe lolbin

<!--more-->


## Known false-positives

* Pnputil.exe being used may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
* Penetration Testing



## References

* https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
* https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbins_suspicious_driver_installed_by_pnputil.yml))
```yaml
title: Suspicious Driver Install by pnputil.exe
status: experimental
id: a2ea3ae7-d3d0-40a0-a55c-25a45c87cac1
author: Hai Vaknin @LuxNoBulIshit, Avihay eldad  @aloneliassaf, Austin Songer @austinsonger
date: 2021/09/30
description: Detects when a possible suspicious driver is being installed via pnputil.exe lolbin
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax
    - https://strontic.github.io/xcyclopedia/library/pnputil.exe-60EDC5E6BDBAEE441F2E3AEACD0340D2.html
tags:
    - attack.persistence
    - attack.t1547
    - attack.t1547.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '-i'
            - '/install'
            - '-a'
            - '/add-driver'
            - '.inf'
        Image|endswith:
            - '\pnputil.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Pnputil.exe being used may be performed by a system administrator. 
    - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
    - Pnputil.exe being executed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
    - Penetration Testing
level: medium

```
