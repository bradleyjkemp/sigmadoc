---
title: "Detection of PowerShell Execution via DLL"
aliases:
  - "/rule/6812a10b-60ea-420c-832f-dfcc33b646ba"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/p3nt4/PowerShdll/blob/master/README.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_dll_execution.yml))
```yaml
title: Detection of PowerShell Execution via DLL
id: 6812a10b-60ea-420c-832f-dfcc33b646ba
status: test
description: Detects PowerShell Strings applied to rundll as seen in PowerShdll.dll
author: Markus Neis
references:
  - https://github.com/p3nt4/PowerShdll/blob/master/README.md
date: 2018/08/25
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith:
      - '\rundll32.exe'
  selection2:
    Description|contains:
      - 'Windows-Hostprozess (Rundll32)'
  selection3:
    CommandLine|contains:
      - 'Default.GetString'
      - 'FromBase64String'
  condition: (selection1 or selection2) and selection3
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011

```
