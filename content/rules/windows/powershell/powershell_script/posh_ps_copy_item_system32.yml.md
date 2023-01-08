---
title: "Powershell Install a DLL in System32"
aliases:
  - "/rule/63bf8794-9917-45bc-88dd-e1b5abc0ecfd"
ruleid: 63bf8794-9917-45bc-88dd-e1b5abc0ecfd

tags:
  - attack.credential_access
  - attack.t1556.002



status: experimental





date: Mon, 27 Dec 2021 20:25:01 +0100


---

Uses PowerShell to install a DLL in System32

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md#atomic-test-1---install-and-register-password-filter-dll


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_copy_item_system32.yml))
```yaml
title: Powershell Install a DLL in System32
id: 63bf8794-9917-45bc-88dd-e1b5abc0ecfd
status: experimental
description: Uses PowerShell to install a DLL in System32
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1556.002/T1556.002.md#atomic-test-1---install-and-register-password-filter-dll
author: frack113
date: 2021/12/27
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains|all:
           - 'Copy-Item '
           - '-Destination '
           - '\Windows\System32'
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.credential_access
    - attack.t1556.002
```
