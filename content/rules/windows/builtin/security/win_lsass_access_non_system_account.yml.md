---
title: "LSASS Access from Non System Account"
aliases:
  - "/rule/962fe167-e48d-4fd6-9974-11e5b9a5d6d1"


tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Sun, 10 Nov 2019 18:43:41 +0300


---

Detects potential mimikatz-like tools accessing LSASS from non system account

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-170105221010.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_lsass_access_non_system_account.yml))
```yaml
title: LSASS Access from Non System Account
id: 962fe167-e48d-4fd6-9974-11e5b9a5d6d1
description: Detects potential mimikatz-like tools accessing LSASS from non system account
status: experimental
date: 2019/06/20
modified: 2021/11/22
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://threathunterplaybook.com/notebooks/windows/06_credential_access/WIN-170105221010.html
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4663
            - 4656
        AccessMask:
            - '0x40'
            - '0x1400'
            # - '0x1000'  # minimum access requirements to query basic info from service
            - '0x100000'
            - '0x1410'    # car.2019-04-004
            - '0x1010'    # car.2019-04-004
            - '0x1438'    # car.2019-04-004
            - '0x143a'    # car.2019-04-004
            - '0x1418'    # car.2019-04-004
            - '0x1f0fff'
            - '0x1f1fff'
            - '0x1f2fff'
            - '0x1f3fff'
            - '40'
            - '1400'
            - '1000'
            - '100000'
            - '1410'    # car.2019-04-004
            - '1010'    # car.2019-04-004
            - '1438'    # car.2019-04-004
            - '143a'    # car.2019-04-004
            - '1418'    # car.2019-04-004
            - '1f0fff'
            - '1f1fff'
            - '1f2fff'
            - '1f3fff'
        ObjectType: 'Process'
        ObjectName|endswith: '\lsass.exe'
    filter1:
        SubjectUserName|endswith: '$'
    filter2:
        ProcessName|startswith: 'C:\Program Files'  # too many false positives with legitimate AV and EDR solutions    
    condition: selection and not 1 of filter*
fields:
    - ComputerName
    - ObjectName
    - SubjectUserName
    - ProcessName
falsepositives:
    - Unknown
level: critical

```