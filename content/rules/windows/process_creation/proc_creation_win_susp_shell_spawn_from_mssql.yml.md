---
title: "Suspicious Shells Spawn by SQL Server"
aliases:
  - "/rule/869b9ca7-9ea2-4a5a-8325-e80e62f75445"


tags:
  - attack.t1505.003
  - attack.t1190
  - attack.initial_access
  - attack.persistence
  - attack.privilege_escalation



status: experimental





date: Fri, 11 Dec 2020 15:17:23 +0700


---

Detects suspicious shell spawn from MSSQL process, this might be sight of RCE or SQL Injection

<!--more-->





## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_from_mssql.yml))
```yaml
title: Suspicious Shells Spawn by SQL Server
id: 869b9ca7-9ea2-4a5a-8325-e80e62f75445
description: Detects suspicious shell spawn from MSSQL process, this might be sight of RCE or SQL Injection
status: experimental
author: FPT.EagleEye Team, wagga
date: 2020/12/11
modified: 2022/03/08
tags:
    - attack.t1505.003
    - attack.t1190
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\sqlservr.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\bitsadmin.exe'
    filter_datev:
        ParentImage|startswith: 'C:\Program Files\Microsoft SQL Server\'
        ParentImage|endswith: 'DATEV_DBENGINE\MSSQL\Binn\sqlservr.exe'
        Image: 'C:\Windows\System32\cmd.exe'
        CommandLine|startswith: '"C:\Windows\system32\cmd.exe" '
    condition: selection and not 1 of filter*
level: critical

```
