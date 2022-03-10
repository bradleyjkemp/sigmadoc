---
title: "Image Load of VSS_PS.dll by Uncommon Executable"
aliases:
  - "/rule/333cdbe8-27bb-4246-bf82-b41a0dca4b70"


tags:
  - attack.defense_evasion
  - attack.impact
  - attack.t1490



status: experimental





date: Wed, 7 Jul 2021 18:21:57 +0200


---

Detects the image load of vss_ps.dll by uncommon executables using OriginalFileName datapoint

<!--more-->


## Known false-positives

* unknown



## References

* 1bd85e1caa1415ebdc8852c91e37bbb7
* https://twitter.com/am0nsec/status/1412232114980982787


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_suspicious_vss_ps_load.yml))
```yaml
title: Image Load of VSS_PS.dll by Uncommon Executable
id: 333cdbe8-27bb-4246-bf82-b41a0dca4b70
status: experimental
description: Detects the image load of vss_ps.dll by uncommon executables using OriginalFileName datapoint
author: Markus Neis, @markus_neis
date: 2021/07/07
modified: 2022/02/21
references:
    - 1bd85e1caa1415ebdc8852c91e37bbb7
    - https://twitter.com/am0nsec/status/1412232114980982787    
tags:
    - attack.defense_evasion
    - attack.impact 
    - attack.t1490
logsource:
    category: image_load
    product: windows
detection:
    selection:
        ImageLoaded|endswith:
            - '\vss_ps.dll'
    filter:
        Image|endswith:
            - '\svchost.exe'
            - '\msiexec.exe'
            - '\vssvc.exe'
            - '\srtasks.exe'
            - '\tiworker.exe'
            - '\dllhost.exe'
            - '\searchindexer.exe'
            - 'dismhost.exe'
            - 'taskhostw.exe'
            - '\clussvc.exe'
            - '\thor64.exe'
            - '\thor.exe'
        Image|contains: 'c:\windows\'
    condition: selection and not filter
falsepositives:
    - unknown
level: high 

```
