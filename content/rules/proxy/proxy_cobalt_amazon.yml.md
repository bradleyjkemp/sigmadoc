---
title: "CobaltStrike Malleable Amazon Browsing Traffic Profile"
aliases:
  - "/rule/953b895e-5cc9-454b-b183-7f3db555452e"

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043



date: Fri, 7 Sep 2018 19:52:35 +0200


---

Detects Malleable Amazon Profile

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/amazon.profile
* https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100


## Raw rule
```yaml
title: CobaltStrike Malleable Amazon Browsing Traffic Profile
id: 953b895e-5cc9-454b-b183-7f3db555452e
status: experimental
description: Detects Malleable Amazon Profile
author: Markus Neis
date: 2019/11/12
modified: 2020/09/02
references:
  - https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/amazon.profile
  - https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100
logsource:
  category: proxy
detection:
  selection1:
    c-useragent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    cs-method: 'GET'
    c-uri: '/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books'
    cs-host: 'www.amazon.com'
    cs-cookie: '*=csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996'
  selection2:
    c-useragent: "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    cs-method: 'POST'
    c-uri: '/N4215/adj/amzn.us.sr.aps'
    cs-host: 'www.amazon.com'
  condition: selection1 or selection2
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043  # an old one
```