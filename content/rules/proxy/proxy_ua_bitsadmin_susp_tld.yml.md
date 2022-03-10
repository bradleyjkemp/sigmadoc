---
title: "Bitsadmin to Uncommon TLD"
aliases:
  - "/rule/9eb68894-7476-4cd6-8752-23b51f5883a7"


tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197
  - attack.s0190



status: experimental





date: Fri, 8 Mar 2019 16:20:10 +0100


---

Detects Bitsadmin connections to domains with uncommon TLDs - https://twitter.com/jhencinski/status/1102695118455349248 - https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/

<!--more-->


## Known false-positives

* Rare programs that use Bitsadmin and update from regional TLDs e.g. .uk or .ca




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_ua_bitsadmin_susp_tld.yml))
```yaml
title: Bitsadmin to Uncommon TLD
id: 9eb68894-7476-4cd6-8752-23b51f5883a7
status: experimental
description: Detects Bitsadmin connections to domains with uncommon TLDs - https://twitter.com/jhencinski/status/1102695118455349248 - https://isc.sans.edu/forums/diary/Investigating+Microsoft+BITS+Activity/23281/
author: Florian Roth
date: 2019/03/07
modified: 2021/08/09
logsource:
    category: proxy
detection:
    selection:
        c-useragent|startswith: 'Microsoft BITS/'
    falsepositives:
        r-dns|endswith:
            - '.com' 
            - '.net' 
            - '.org' 
    condition: selection and not falsepositives
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - Rare programs that use Bitsadmin and update from regional TLDs e.g. .uk or .ca
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
    - attack.s0190

```