---
title: "Credential Dumping by Pypykatz"
aliases:
  - "/rule/7186e989-4ed7-4f4e-a656-4674b9e3e48b"


tags:
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Tue, 3 Aug 2021 15:06:27 +0545


---

Detects LSASS process access by pypykatz for credential dumping.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/skelsec/pypykatz


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_pypykatz_cred_dump_lsass_access.yml))
```yaml
title: Credential Dumping by Pypykatz
id: 7186e989-4ed7-4f4e-a656-4674b9e3e48b
description: Detects LSASS process access by pypykatz for credential dumping.
status: experimental
date: 2021/08/03
author: Bhabesh Raj
references:
    - https://github.com/skelsec/pypykatz
tags:
    - attack.credential_access
    - attack.t1003.001
logsource:
    category: process_access
    product: windows
detection:
    selection: 
        TargetImage|endswith: '\lsass.exe'
        CallTrace|contains|all: 
            - 'C:\Windows\SYSTEM32\ntdll.dll+'
            - 'C:\Windows\System32\KERNELBASE.dll+'
            - 'libffi-7.dll'
            - '_ctypes.pyd+'
            - 'python3*.dll+'   # Pypy requires python>=3.6
        GrantedAccess: '0x1FFFFF'
    condition: selection
level: critical
falsepositives:
    - Unknown
```
