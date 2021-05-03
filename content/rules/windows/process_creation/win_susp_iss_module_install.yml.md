---
title: "IIS Native-Code Module Command Line Installation"
aliases:
  - "/rule/9465ddf4-f9e4-4ebd-8d98-702df3a93239"

tags:
  - attack.persistence
  - attack.t1505.003
  - attack.t1100



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious IIS native-code module installations via command line

<!--more-->


## Known false-positives

* Unknown as it may vary from organisation to arganisation how admins use to install IIS modules



## References

* https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/


## Raw rule
```yaml
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
description: Detects suspicious IIS native-code module installations via command line
status: experimental
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
author: Florian Roth
date: 2012/12/11
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.t1100      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\APPCMD.EXE install module /name:*'
    condition: selection
falsepositives:
    - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium

```
