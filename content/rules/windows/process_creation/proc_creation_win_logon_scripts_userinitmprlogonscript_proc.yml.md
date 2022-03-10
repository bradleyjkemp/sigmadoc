---
title: "Logon Scripts (UserInitMprLogonScript)"
aliases:
  - "/rule/0a98a10c-685d-4ab0-bddc-b6bdd1d48458"


tags:
  - attack.t1037.001
  - attack.persistence



status: test





date: Sat, 12 Jan 2019 12:01:03 +0100


---

Detects creation or execution of UserInitMprLogonScript persistence method

<!--more-->


## Known false-positives

* exclude legitimate logon scripts
* penetration tests, red teaming



## References

* https://attack.mitre.org/techniques/T1037/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_logon_scripts_userinitmprlogonscript_proc.yml))
```yaml
title: Logon Scripts (UserInitMprLogonScript)
id: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
status: test
description: Detects creation or execution of UserInitMprLogonScript persistence method
author: Tom Ueltschi (@c_APT_ure)
references:
  - https://attack.mitre.org/techniques/T1037/
date: 2019/01/12
modified: 2022/02/21
logsource:
  category: process_creation
  product: windows
detection:
  exec_selection:
    ParentImage|endswith: '\userinit.exe'
  exec_exclusion1:
    Image|endswith: 
      - 'explorer.exe'
      - '\proquota.exe'
  exec_exclusion2:
    CommandLine|contains:
      - 'netlogon*.bat'
      - 'UsrLogon.cmd'
      - 'C:\WINDOWS\Explorer.EXE'
  create_keywords_cli:
    CommandLine|contains: 'UserInitMprLogonScript'
  condition: ( exec_selection and not 1 of exec_exclusion* ) or create_keywords_cli
falsepositives:
  - exclude legitimate logon scripts
  - penetration tests, red teaming
level: high
tags:
  - attack.t1037.001
  - attack.persistence

```
