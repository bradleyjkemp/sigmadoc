---
title: "Wannacry Killswitch Domain"
aliases:
  - "/rule/c64c5175-5189-431b-a55e-6d9882158251"

tags:
  - attack.command_and_control
  - attack.t1071.001



status: experimental



level: high



date: Wed, 16 Sep 2020 20:32:31 -0600


---

Detects wannacry killswitch domain dns queries

<!--more-->


## Known false-positives

* Analyst testing



## References

* https://www.fireeye.com/blog/products-and-services/2017/05/wannacry-ransomware-campaign.html


## Raw rule
```yaml
title: Wannacry Killswitch Domain
id: c64c5175-5189-431b-a55e-6d9882158251
status: experimental
description: Detects wannacry killswitch domain dns queries
references:
    - https://www.fireeye.com/blog/products-and-services/2017/05/wannacry-ransomware-campaign.html
author: Mike Wade
date: 2020/09/16
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query:
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.testing'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.test'
            - 'ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
            - 'ayylmaotjhsstasdfasdfasdfasdfasdfasdfasdf.com'
            - 'iuqssfsodp9ifjaposdfjhgosurijfaewrwergwea.com'
            - ''
    condition: selection
falsepositives:
    - Analyst testing 
level: high
```
