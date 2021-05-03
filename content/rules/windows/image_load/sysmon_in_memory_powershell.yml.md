---
title: "In-memory PowerShell"
aliases:
  - "/rule/092bc4b9-3d1d-43b4-a6b4-8c8acd83522f"

tags:
  - attack.t1086
  - attack.t1059.001
  - attack.execution



date: Sun, 1 Dec 2019 23:26:00 +0100


---

Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension.

<!--more-->


## Known false-positives

* Used by some .NET binaries, minimal on user workstation.



## References

* https://adsecurity.org/?p=2921
* https://github.com/p3nt4/PowerShdll


## Raw rule
```yaml
title: In-memory PowerShell
id: 092bc4b9-3d1d-43b4-a6b4-8c8acd83522f
status: experimental
description: Detects loading of essential DLL used by PowerShell, but not by the process powershell.exe. Detects meterpreter's "load powershell" extension.
author: Tom Kern, oscd.community
date: 2019/11/14
modified: 2019/11/30
references:
    - https://adsecurity.org/?p=2921
    - https://github.com/p3nt4/PowerShdll
tags:
    - attack.t1086          # an old one
    - attack.t1059.001
    - attack.execution
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\System.Management.Automation.Dll'
            - '\System.Management.Automation.ni.Dll'
    filter:
        Image|endswith:
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\WINDOWS\System32\sdiagnhost.exe'
            - '\mscorsvw.exe'  # c:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsw.exe for instance
            - '\WINDOWS\System32\RemoteFXvGPUDisablement.exe'  # on win10
       # User: 'NT AUTHORITY\SYSTEM'   # if set, matches all powershell processes not launched by SYSTEM
    condition: selection and not filter
falsepositives:
    - Used by some .NET binaries, minimal on user workstation.
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                      # http://bit.ly/314zc6x
    - EN_0003_enrich_other_sysmon_events_with_event_id_1_data   # http://bit.ly/2ojW7fw

```
