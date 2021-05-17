---
title: "Cisco Crypto Commands"
aliases:
  - "/rule/1f978c6a-4415-47fb-aca5-736a44d7ca3d"

tags:
  - attack.credential_access
  - attack.defense_evasion
  - attack.t1130
  - attack.t1553.004
  - attack.t1145
  - attack.t1552.004



status: experimental



level: high



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Show when private keys are being exported from the device, or when new certificates are installed

<!--more-->


## Known false-positives

* Not commonly run by administrators. Also whitelist your known good certificates




## Raw rule
```yaml
title: Cisco Crypto Commands
id: 1f978c6a-4415-47fb-aca5-736a44d7ca3d
status: experimental
description: Show when private keys are being exported from the device, or when new certificates are installed
author: Austin Clark
date: 2019/08/12
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
detection:
    keywords:
        - 'crypto pki export'
        - 'crypto pki import'
        - 'crypto pki trustpoint'
    condition: keywords
falsepositives:
    - Not commonly run by administrators. Also whitelist your known good certificates
level: high
tags:
    - attack.credential_access
    - attack.defense_evasion
    - attack.t1130          # an old one
    - attack.t1553.004
    - attack.t1145          # an old one
    - attack.t1552.004
```
