---
title: "Wannacry Killswitch Domain"
aliases:
  - "/rule/3eaf6218-3bed-4d8a-8707-274096f12a18"
ruleid: 3eaf6218-3bed-4d8a-8707-274096f12a18

tags:
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Wed, 16 Sep 2020 20:32:31 -0600


---

Detects wannacry killswitch domain dns queries

<!--more-->


## Known false-positives

* Analyst testing



## References

* https://www.fireeye.com/blog/products-and-services/2017/05/wannacry-ransomware-campaign.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_wannacry_killswitch_domain.yml))
```yaml
title: Wannacry Killswitch Domain
id: 3eaf6218-3bed-4d8a-8707-274096f12a18
status: test
description: Detects wannacry killswitch domain dns queries
author: Mike Wade
references:
  - https://www.fireeye.com/blog/products-and-services/2017/05/wannacry-ransomware-campaign.html
date: 2020/09/16
modified: 2021/11/27
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
tags:
  - attack.command_and_control
  - attack.t1071.001

```
