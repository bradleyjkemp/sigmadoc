---
title: "CobaltStrike Malformed UAs in Malleable Profiles"
aliases:
  - "/rule/41b42a36-f62c-4c34-bd40-8cb804a34ad8"


tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects different malformed user agents used in Malleable Profiles used with Cobalt Strike

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/yeyintminthuhtut/Malleable-C2-Profiles-Collection/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_cobalt_malformed_uas.yml))
```yaml
title: CobaltStrike Malformed UAs in Malleable Profiles
id: 41b42a36-f62c-4c34-bd40-8cb804a34ad8
status: experimental
description: Detects different malformed user agents used in Malleable Profiles used with Cobalt Strike
author: Florian Roth
date: 2021/05/06
modified: 2021/11/02
references:
  - https://github.com/yeyintminthuhtut/Malleable-C2-Profiles-Collection/
logsource:
  category: proxy
detection:
  selection1:
    c-useragent: 
      - 'Mozilla/4.0 (compatible; MSIE 6.0;Windows NT 5.1)'
      - 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E )'
      - 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2) Java/1.5.0_08'
  selection2:
    c-useragent|endswith: '; MANM; MANM)'
  condition: 1 of selection*
falsepositives:
  - Unknown
level: critical
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001

```