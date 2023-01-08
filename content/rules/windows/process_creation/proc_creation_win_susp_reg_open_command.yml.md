---
title: "Suspicious Reg Add Open Command"
aliases:
  - "/rule/dd3ee8cc-f751-41c9-ba53-5a32ed47e563"
ruleid: dd3ee8cc-f751-41c9-ba53-5a32ed47e563

tags:
  - attack.credential_access
  - attack.t1003



status: experimental





date: Mon, 20 Dec 2021 18:59:11 +0100


---

Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key

<!--more-->


## Known false-positives

* unknown



## References

* https://thedfirreport.com/2021/12/13/diavol-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_reg_open_command.yml))
```yaml
title: Suspicious Reg Add Open Command
id: dd3ee8cc-f751-41c9-ba53-5a32ed47e563
status: experimental
description: Threat actors performed dumping of SAM, SECURITY and SYSTEM registry hives using DelegateExecute key
references:
    - https://thedfirreport.com/2021/12/13/diavol-ransomware/
author: frack113
date: 2021/12/20
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
            - 'hkcu\software\classes\ms-settings\shell\open\command'
            - '/ve '
            - '/d'
    selection_2:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
            - 'hkcu\software\classes\ms-settings\shell\open\command' 
            - '/v'
            - 'DelegateExecute'
    selection_3:
        CommandLine|contains|all:
            - 'reg'
            - 'delete'
            - 'hkcu\software\classes\ms-settings'
    condition: 1 of selection_*
falsepositives:
    - unknown
level: medium
tags:
    - attack.credential_access
    - attack.t1003

```
