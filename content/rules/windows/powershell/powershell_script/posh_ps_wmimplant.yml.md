---
title: "WMImplant Hack Tool"
aliases:
  - "/rule/8028c2c3-e25a-46e3-827f-bbb5abf181d7"
ruleid: 8028c2c3-e25a-46e3-827f-bbb5abf181d7

tags:
  - attack.execution
  - attack.t1047
  - attack.t1059.001



status: experimental





date: Fri, 27 Mar 2020 15:08:35 +0100


---

Detects parameters used by WMImplant

<!--more-->


## Known false-positives

* Administrative scripts that use the same keywords.



## References

* https://github.com/FortyNorthSecurity/WMImplant


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_wmimplant.yml))
```yaml
title: WMImplant Hack Tool
id: 8028c2c3-e25a-46e3-827f-bbb5abf181d7
status: experimental
description: Detects parameters used by WMImplant
references:
  - https://github.com/FortyNorthSecurity/WMImplant
tags:
  - attack.execution
  - attack.t1047
  - attack.t1059.001
author: NVISO
date: 2020/03/26
modified: 2021/10/16
logsource:
  product: windows
  category: ps_script
  definition: Script block logging must be enabled
detection:
  selection:
    ScriptBlockText|contains:
      - 'WMImplant'
      - ' change_user '
      - ' gen_cli '
      - ' command_exec '
      - ' disable_wdigest '
      - ' disable_winrm '
      - ' enable_wdigest '
      - ' enable_winrm '
      - ' registry_mod '
      - ' remote_posh '
      - ' sched_job '
      - ' service_mod '
      - ' process_kill '
      # - ' process_start '
      - ' active_users '
      - ' basic_info '
      # - ' drive_list '
      # - ' installed_programs '
      - ' power_off '
      - ' vacant_system '
      - ' logon_events '
  condition: selection
falsepositives:
  - Administrative scripts that use the same keywords.
level: high

```
