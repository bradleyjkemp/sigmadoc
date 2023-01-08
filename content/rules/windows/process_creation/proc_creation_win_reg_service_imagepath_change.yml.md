---
title: "Service ImagePath Change with Reg.exe"
aliases:
  - "/rule/9b0b7ac3-6223-47aa-a3fd-e8f211e637db"
ruleid: 9b0b7ac3-6223-47aa-a3fd-e8f211e637db

tags:
  - attack.persistence
  - attack.t1574.011



status: experimental





date: Thu, 30 Dec 2021 11:58:10 +0100


---

Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.011/T1574.011.md#atomic-test-2---service-imagepath-change-with-regexe


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_reg_service_imagepath_change.yml))
```yaml
title: Service ImagePath Change with Reg.exe
id: 9b0b7ac3-6223-47aa-a3fd-e8f211e637db
status: experimental
description: |
  Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services.
  Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.
  Windows stores local service configuration information in the Registry under HKLM\SYSTEM\CurrentControlSet\Services
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.011/T1574.011.md#atomic-test-2---service-imagepath-change-with-regexe
author: frack113
date: 2021/12/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \reg.exe 
        CommandLine|contains|all:
            - 'add '
            - 'HKLM\SYSTEM\CurrentControlSet\Services\'
            - '/v '
            - 'ImagePath '
            - '/d '
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
  - attack.persistence
  - attack.t1574.011
```
