---
title: "Generic Password Dumper Activity on LSASS"
aliases:
  - "/rule/4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76"


tags:
  - attack.credential_access
  - car.2019-04-004
  - attack.t1003.001



status: experimental





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Detects process handle on LSASS process with certain access mask

<!--more-->


## Known false-positives

* Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it



## References

* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_lsass_dump_generic.yml))
```yaml
title: Generic Password Dumper Activity on LSASS
id: 4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76
description: Detects process handle on LSASS process with certain access mask
status: experimental
author: Roberto Rodriguez, Teymur Kheirkhabarov, Dimitrios Slamaris, Mark Russinovich, Aleksey Potapov, oscd.community (update)
date: 2019/11/01
modified: 2021/11/22
references:
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - car.2019-04-004
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection_1:
        EventID: 4656
        ObjectName|endswith: '\lsass.exe'
        AccessMask|contains:
            - '0x40'
            - '0x1400'
            # - '0x1000'  # minimum access requirements to query basic info from service
            - '0x100000'
            - '0x1410'    # car.2019-04-004
            - '0x1010'    # car.2019-04-004
            - '0x1438'    # car.2019-04-004
            - '0x143a'    # car.2019-04-004
            - '0x1418'    # car.2019-04-004
            - '0x1f0fff'
            - '0x1f1fff'
            - '0x1f2fff'
            - '0x1f3fff'
    selection_2:
        EventID: 4663
        ObjectName|endswith: '\lsass.exe'
        AccessList|contains:
            - '4484'
            - '4416'
    filter1:
        ProcessName|endswith:
            - '\wmiprvse.exe'
            - '\taskmgr.exe'
            - '\procexp64.exe'
            - '\procexp.exe'
            - '\lsm.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\vmtoolsd.exe'
            - '\minionhost.exe'  # Cyberreason
            - '\VsTskMgr.exe'    # McAfee Enterprise
            - '\thor64.exe'      # THOR
            - '\MicrosoftEdgeUpdate.exe'
            - '\GamingServices.exe'
            - '\svchost.exe'
            - '\MsMpEng.exe'     # Defender
        ProcessName|startswith:
            - C:\Windows\System32\
            - C:\Windows\SysWow64\
            - C:\Windows\SysNative\
            - C:\Program Files\
            - C:\Windows\Temp\asgard2-agent\
            - C:\ProgramData\Microsoft\Windows Defender\Platform\
    filter2:
        ProcessName|startswith:
            - 'C:\Program Files'  # too many false positives with legitimate AV and EDR solutions
    condition: 1 of selection_* and not 1 of filter*
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ProcessName
    - ProcessID
falsepositives:
    - Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it
level: high

```
