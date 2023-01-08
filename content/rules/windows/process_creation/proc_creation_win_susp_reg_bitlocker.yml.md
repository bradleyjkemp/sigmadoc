---
title: "Suspicious Reg Add BitLocker"
aliases:
  - "/rule/0e0255bf-2548-47b8-9582-c0955c9283f5"
ruleid: 0e0255bf-2548-47b8-9582-c0955c9283f5

tags:
  - attack.impact
  - attack.t1486



status: experimental





date: Mon, 15 Nov 2021 13:24:26 +0100


---

Suspicious add key for BitLocker

<!--more-->


## Known false-positives

* unknown



## References

* https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_reg_bitlocker.yml))
```yaml
title: Suspicious Reg Add BitLocker
id: 0e0255bf-2548-47b8-9582-c0955c9283f5
status: experimental
description: Suspicious add key for BitLocker
references:
    - https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/
tags:
    - attack.impact
    - attack.t1486
author: frack113
date: 2021/11/15
logsource:
    category: process_creation
    product: windows
detection:
    set:
        CommandLine|contains|all:
            - 'REG'
            - 'ADD'
            - 'HKLM\SOFTWARE\Policies\Microsoft\FVE'
            - '/v'
            - '/f'
    key:
        CommandLine|contains:
            - 'EnableBDEWithNoTPM'
            - 'UseAdvancedStartup'
            - 'UseTPM'
            - 'UseTPMKey'
            - 'UseTPMKeyPIN'
            - 'RecoveryKeyMessageSource'
            - 'UseTPMPIN'
            - 'RecoveryKeyMessage'
    condition: set and key
falsepositives:
    - unknown
level: medium

```
