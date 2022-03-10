---
title: "Cisco Crypto Commands"
aliases:
  - "/rule/1f978c6a-4415-47fb-aca5-736a44d7ca3d"


tags:
  - attack.credential_access
  - attack.defense_evasion
  - attack.t1553.004
  - attack.t1552.004



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Show when private keys are being exported from the device, or when new certificates are installed

<!--more-->


## Known false-positives

* Not commonly run by administrators. Also whitelist your known good certificates




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_crypto_actions.yml))
```yaml
title: Cisco Crypto Commands
id: 1f978c6a-4415-47fb-aca5-736a44d7ca3d
status: test
description: Show when private keys are being exported from the device, or when new certificates are installed
author: Austin Clark
date: 2019/08/12
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'crypto pki export'
    - 'crypto pki import'
    - 'crypto pki trustpoint'
  condition: keywords
fields:
  - src
  - CmdSet
  - User
  - Privilege_Level
  - Remote_Address
falsepositives:
  - Not commonly run by administrators. Also whitelist your known good certificates
level: high
tags:
  - attack.credential_access
  - attack.defense_evasion
  - attack.t1553.004
  - attack.t1552.004

```