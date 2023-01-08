---
title: "AdFind Usage Detection"
aliases:
  - "/rule/9a132afa-654e-11eb-ae93-0242ac130002"
ruleid: 9a132afa-654e-11eb-ae93-0242ac130002

tags:
  - attack.discovery
  - attack.t1482
  - attack.t1018



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.

<!--more-->


## Known false-positives

* Admin activity



## References

* https://thedfirreport.com/2020/05/08/adfind-recon/
* https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
* https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_ad_find_discovery.yml))
```yaml
title: AdFind Usage Detection
id: 9a132afa-654e-11eb-ae93-0242ac130002
status: test
description: AdFind continues to be seen across majority of breaches. It is used to domain trust discovery to plan out subsequent steps in the attack chain.
author: Janantha Marasinghe (https://github.com/blueteam0ps)
references:
    - https://thedfirreport.com/2020/05/08/adfind-recon/
    - https://thedfirreport.com/2021/01/11/trickbot-still-alive-and-well/
    - https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
date: 2021/02/02
modified: 2021/02/02
tags:
    - attack.discovery
    - attack.t1482
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:  
            - 'domainlist'
            - 'trustdmp'
            - 'dcmodes'
            - 'adinfo'
            - ' dclist '
            - 'computer_pwdnotreqd'
            - 'objectcategory='
            - '-subnets -f'
            - 'name="Domain Admins"'
            - '-sc u:'
            - 'domainncs'
            - 'dompol'
            - ' oudmp '
            - 'subnetdmp'
            - 'gpodmp'
            - 'fspdmp'
            - 'users_noexpire'
            - 'computers_active'
    condition: selection
falsepositives:
    - Admin activity
level: high

```
