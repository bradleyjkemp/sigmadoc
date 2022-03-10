---
title: "Empty User Agent"
aliases:
  - "/rule/21e44d78-95e7-421b-a464-ffd8395659c4"


tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001



status: test





date: Sat, 8 Jul 2017 08:37:44 -0600


---

Detects suspicious empty user agent strings in proxy logs

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/Carlos_Perez/status/883455096645931008


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_empty_ua.yml))
```yaml
title: Empty User Agent
id: 21e44d78-95e7-421b-a464-ffd8395659c4
status: test
description: Detects suspicious empty user agent strings in proxy logs
author: Florian Roth
references:
  - https://twitter.com/Carlos_Perez/status/883455096645931008
date: 2017/07/08
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
      # Empty string - as used by Powershell's (New-Object Net.WebClient).DownloadString
    c-useragent: ''
  condition: selection
fields:
  - ClientIP
  - c-uri
  - c-useragent
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1071.001

```
