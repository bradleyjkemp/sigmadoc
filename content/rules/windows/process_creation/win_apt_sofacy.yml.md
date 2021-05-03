---
title: "Sofacy Trojan Loader Activity"
aliases:
  - "/rule/ba778144-5e3d-40cf-8af9-e28fb1df1e20"

tags:
  - attack.g0007
  - attack.execution
  - attack.t1059
  - attack.t1059.003
  - attack.defense_evasion
  - attack.t1085
  - car.2013-10-002
  - attack.t1218.011



date: Thu, 1 Mar 2018 09:27:46 +0100


---

Detects Trojan loader acitivty as used by APT28

<!--more-->


## Known false-positives

* Unknown



## References

* https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/
* https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100
* https://twitter.com/ClearskySec/status/960924755355369472


## Raw rule
```yaml
title: Sofacy Trojan Loader Activity
id: ba778144-5e3d-40cf-8af9-e28fb1df1e20
author: Florian Roth
status: experimental
date: 2018/03/01
modified: 2020/08/27
description: Detects Trojan loader acitivty as used by APT28
references:
    - https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/
    - https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100
    - https://twitter.com/ClearskySec/status/960924755355369472
tags:
    - attack.g0007
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1059.003
    - attack.defense_evasion
    - attack.t1085 # an old one
    - car.2013-10-002
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'rundll32.exe %APPDATA%\\*.dat",*'
            - 'rundll32.exe %APPDATA%\\*.dll",#1'
    condition: selection
falsepositives:
    - Unknown
level: critical

```