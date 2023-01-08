---
title: "DNS Query for MEGA.io Upload Domain"
aliases:
  - "/rule/613c03ba-0779-4a53-8a1f-47f914a4ded3"
ruleid: 613c03ba-0779-4a53-8a1f-47f914a4ded3

tags:
  - attack.exfiltration
  - attack.t1567.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects DNS queries for subdomains used for upload to MEGA.io

<!--more-->


## Known false-positives

* Legitimate Mega upload



## References

* https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_mega_nz.yml))
```yaml
title: DNS Query for MEGA.io Upload Domain
id: 613c03ba-0779-4a53-8a1f-47f914a4ded3
description: Detects DNS queries for subdomains used for upload to MEGA.io
status: experimental
date: 2021/05/26
author: Aaron Greetham (@beardofbinary) - NCC Group
references:
    - https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/
tags:
    - attack.exfiltration
    - attack.t1567.002
falsepositives:
    - Legitimate Mega upload
level: high
logsource:
    product: windows
    category: dns_query
detection:
    dns_request:
        QueryName|contains: userstorage.mega.co.nz
    condition: dns_request
```
