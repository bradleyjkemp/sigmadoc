---
title: "Raw Paste Service Access"
aliases:
  - "/rule/5468045b-4fcc-4d1a-973c-c9c9578edacb"

tags:
  - attack.command_and_control
  - attack.t1071.001
  - attack.t1043
  - attack.t1102.001
  - attack.t1102.003
  - attack.defense_evasion
  - attack.t1102



status: experimental



level: high



date: Thu, 5 Dec 2019 08:54:42 +0100


---

Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form

<!--more-->


## Known false-positives

* User activity (e.g. developer that shared and copied code snippets and used the raw link instead of just copy & paste)



## References

* https://www.virustotal.com/gui/domain/paste.ee/relations


## Raw rule
```yaml
title: Raw Paste Service Access
id: 5468045b-4fcc-4d1a-973c-c9c9578edacb
status: experimental
description: Detects direct access to raw pastes in different paste services often used by malware in their second stages to download malicious code in encrypted or encoded form
author: Florian Roth
date: 2019/12/05
modified: 2020/09/03
references:
    - https://www.virustotal.com/gui/domain/paste.ee/relations
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 
          - '.paste.ee/r/'
          - '.pastebin.com/raw/'
          - '.hastebin.com/raw/'
          - '.ghostbin.co/paste/*/raw/'
    condition: selection
fields:
    - ClientIP
    - c-uri
    - c-useragent
falsepositives:
    - User activity (e.g. developer that shared and copied code snippets and used the raw link instead of just copy & paste)
level: high
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1043  # an old one
    - attack.t1102.001
    - attack.t1102.003
    - attack.defense_evasion
    - attack.t1102  # an old one
```
