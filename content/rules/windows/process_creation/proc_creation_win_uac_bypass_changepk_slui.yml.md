---
title: "UAC Bypass Using ChangePK and SLUI"
aliases:
  - "/rule/503d581c-7df0-4bbe-b9be-5840c0ecc1fc"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)

<!--more-->


## Known false-positives

* Unknown



## References

* https://mattharr0ey.medium.com/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
* https://github.com/hfiref0x/UACME
* https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_changepk_slui.yml))
```yaml
title: UAC Bypass Using ChangePK and SLUI
id: 503d581c-7df0-4bbe-b9be-5840c0ecc1fc
description: Detects an UAC bypass that uses changepk.exe and slui.exe (UACMe 61)
author: Christian Burkard
date: 2021/08/23
status: experimental
references:
    - https://mattharr0ey.medium.com/privilege-escalation-uac-bypass-in-changepk-c40b92818d1b
    - https://github.com/hfiref0x/UACME
    - https://medium.com/falconforce/falconfriday-detecting-uac-bypasses-0xff16-86c2a9107abf
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\changepk.exe'
        ParentImage|endswith: '\slui.exe'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
