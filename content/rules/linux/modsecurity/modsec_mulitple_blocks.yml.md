---
title: "Multiple Modsecurity Blocks"
aliases:
  - "/rule/a06eea10-d932-4aa6-8ba9-186df72c8d23"


tags:
  - attack.impact
  - attack.t1499



status: stable





date: Tue, 28 Feb 2017 17:53:32 +0100


---

Detects multiple blocks by the mod_security module (Web Application Firewall)

<!--more-->


## Known false-positives

* Vulnerability scanners
* Frequent attacks if system faces Internet




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/modsecurity/modsec_mulitple_blocks.yml))
```yaml
title: Multiple Modsecurity Blocks
id: a06eea10-d932-4aa6-8ba9-186df72c8d23
status: stable
description: Detects multiple blocks by the mod_security module (Web Application Firewall)
author: Florian Roth
date: 2017/02/28
logsource:
    product: linux
    service: modsecurity
detection:
    selection:
        - 'mod_security: Access denied'
        - 'ModSecurity: Access denied'
        - 'mod_security-message: Access denied'
    timeframe: 120m
    condition: selection | count() > 6
falsepositives:
    - Vulnerability scanners
    - Frequent attacks if system faces Internet
level: medium
tags:
    - attack.impact
    - attack.t1499 
```
