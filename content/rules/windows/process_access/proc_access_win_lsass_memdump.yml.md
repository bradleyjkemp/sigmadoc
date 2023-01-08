---
title: "LSASS Memory Dump"
aliases:
  - "/rule/5ef9853e-4d0e-4a70-846f-a9ca37d876da"
ruleid: 5ef9853e-4d0e-4a70-846f-a9ca37d876da

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0002



status: experimental





date: Wed, 3 Apr 2019 13:51:59 +0200


---

Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll for win10, server2016 and up.

<!--more-->


## Known false-positives

* False positives are present when looking for 0x1410. Exclusions may be required.



## References

* https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
* https://research.splunk.com/endpoint/windows_possible_credential_dumping/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml))
```yaml
title: LSASS Memory Dump
id: 5ef9853e-4d0e-4a70-846f-a9ca37d876da
status: experimental
description: Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll for win10, server2016 and up.
author: Samir Bousseaden, Michael Haag
date: 2019/04/03
modified: 2022/02/05
references:
    - https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003.001/T1003.001.md
    - https://research.splunk.com/endpoint/windows_possible_credential_dumping/
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains: 
            #- '0x1fffff' # Too many false positives
            #- '0x01000'  # Too many false positives
            #- '0x1010'   # Too many false positives
            - '0x1038'
            - '0x40'
            #- '0x1400'  # Too many false positives
            # - '0x1410' # Too many false positives 
            - '0x1438'
            - '0x143a'
        CallTrace|contains:
            - 'dbghelp.dll'
            - 'dbgcore.dll'
            - 'ntdll.dll'
    condition: selection
falsepositives:
    - False positives are present when looking for 0x1410. Exclusions may be required.
level: high
```
