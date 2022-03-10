---
title: "Time Travel Debugging Utility Usage"
aliases:
  - "/rule/e76c8240-d68f-4773-8880-5c6f63595aaf"


tags:
  - attack.defense_evasion
  - attack.credential_access
  - attack.t1218
  - attack.t1003.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.

<!--more-->


## Known false-positives

* Legitimate usage by software developers/testers



## References

* https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
* https://twitter.com/mattifestation/status/1196390321783025666
* https://twitter.com/oulusoyum/status/1191329746069655553


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_tttracer_mod_load.yml))
```yaml
title: Time Travel Debugging Utility Usage
id: e76c8240-d68f-4773-8880-5c6f63595aaf
status: experimental
description: Detects usage of Time Travel Debugging Utility. Adversaries can execute malicious processes and dump processes, such as lsass.exe, via tttracer.exe.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Tttracer/
    - https://twitter.com/mattifestation/status/1196390321783025666
    - https://twitter.com/oulusoyum/status/1191329746069655553
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative' 
date: 2020/10/06
modified: 2021/09/21
tags:
    - attack.defense_evasion
    - attack.credential_access
    - attack.t1218
    - attack.t1003.001
logsource:
    product: windows
    category: image_load
detection:
    selection:
       ImageLoaded|endswith:
          - '\ttdrecord.dll'
          - '\ttdwriter.dll'
          - '\ttdloader.dll'
    condition: selection
falsepositives:
    - Legitimate usage by software developers/testers
level: high
```
