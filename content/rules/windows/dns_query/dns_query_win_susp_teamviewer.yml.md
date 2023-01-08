---
title: "Suspicious TeamViewer Domain Access"
aliases:
  - "/rule/778ba9a8-45e4-4b80-8e3e-34a419f0b85e"
ruleid: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e

tags:
  - attack.command_and_control
  - attack.t1219



status: experimental





date: Sun, 30 Jan 2022 22:05:47 +0100


---

Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)

<!--more-->


## Known false-positives

* Unknown binary names of TeamViewer
* Other programs that also lookup the observed domain



## References

* https://www.teamviewer.com/en-us/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_susp_teamviewer.yml))
```yaml
title: Suspicious TeamViewer Domain Access
id: 778ba9a8-45e4-4b80-8e3e-34a419f0b85e
description: Detects DNS queries to a TeamViewer domain only resolved by a TeamViewer client by an image that isn't named TeamViewer (sometimes used by threat actors for obfuscation)
status: experimental
date: 2022/01/30
modified: 2022/02/08
author: Florian Roth
references:
    - https://www.teamviewer.com/en-us/
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    product: windows
    category: dns_query
detection:
    dns_request:
        QueryName: 
            - 'taf.teamviewer.com'
            - 'udp.ping.teamviewer.com'
    filter:
        Image|contains: 'TeamViewer'
    condition: dns_request and not filter
falsepositives:
    - Unknown binary names of TeamViewer
    - Other programs that also lookup the observed domain
level: medium
```
