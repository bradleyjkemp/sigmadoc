---
title: "Credential Dumping by LaZagne"
aliases:
  - "/rule/4b9a8556-99c4-470b-a40c-9c8d02c77ed0"
ruleid: 4b9a8556-99c4-470b-a40c-9c8d02c77ed0

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0349



status: stable





date: Wed, 9 Sep 2020 18:27:14 +0545


---

Detects LSASS process access by LaZagne for credential dumping.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/bh4b3sh/status/1303674603819081728


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_lazagne_cred_dump_lsass_access.yml))
```yaml
title: Credential Dumping by LaZagne
id: 4b9a8556-99c4-470b-a40c-9c8d02c77ed0
description: Detects LSASS process access by LaZagne for credential dumping.
status: stable
date: 2020/09/09
author: Bhabesh Raj, Jonhnathan Ribeiro
references:
    - https://twitter.com/bh4b3sh/status/1303674603819081728
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0349
logsource:
    category: process_access
    product: windows
detection:
    selection: 
        TargetImage|endswith: '\lsass.exe'
        CallTrace|contains|all: 
            - 'C:\\Windows\\SYSTEM32\\ntdll.dll+'
            - '|C:\\Windows\\System32\\KERNELBASE.dll+'
            - '_ctypes.pyd+'
            - 'python27.dll+'
        GrantedAccess: '0x1FFFFF'
    condition: selection
level: critical
falsepositives:
    - Unknown

```
