---
title: "Mimikatz Use"
aliases:
  - "/rule/06d71506-7beb-4f22-8888-e2e5e2ca7fd8"


tags:
  - attack.s0002
  - attack.lateral_movement
  - attack.credential_access
  - car.2013-07-001
  - car.2019-04-004
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.001
  - attack.t1003.006



status: experimental





date: Tue, 27 Dec 2016 14:49:54 +0100


---

This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)

<!--more-->


## Known false-positives

* Naughty administrators
* Penetration test
* AV Signature updates
* Files with Mimikatz in their filename



## References

* https://tools.thehacker.recipes/mimikatz/modules


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/win_alert_mimikatz_keywords.yml))
```yaml
title: Mimikatz Use
id: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8
description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)
status: experimental
author: Florian Roth (rule), David ANDRE (additional keywords)
date: 2017/01/10
modified: 2022/01/05
references:
    - https://tools.thehacker.recipes/mimikatz/modules
tags:
    - attack.s0002
    - attack.lateral_movement
    - attack.credential_access
    - car.2013-07-001
    - car.2019-04-004
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.001
    - attack.t1003.006
logsource:
    product: windows
detection:
    keywords:
        - 'dpapi::masterkey'
        - 'eo.oe.kiwi'
        - 'event::clear'
        - 'event::drop'
        - 'gentilkiwi.com'
        - 'kerberos::golden'
        - 'kerberos::ptc'
        - 'kerberos::ptt'
        - 'kerberos::tgt'
        - 'Kiwi Legit Printer'
        - 'lsadump::'
        - 'mimidrv.sys'
        - '\mimilib.dll'
        - 'misc::printnightmare'
        - 'misc::shadowcopies'
        - 'misc::skeleton'
        - 'privilege::backup'
        - 'privilege::debug'
        - 'privilege::driver'
        - 'sekurlsa::'
    filter:
        EventID: 15  # Sysmon's FileStream Events (could cause false positives when Sigma rules get copied on/to a system)
    condition: keywords and not filter
falsepositives:
    - Naughty administrators
    - Penetration test
    - AV Signature updates
    - Files with Mimikatz in their filename
level: critical

```