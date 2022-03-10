---
title: "Possible DNS Tunneling"
aliases:
  - "/rule/1ec4b281-aa65-46a2-bdae-5fd830ed914e"


tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003



status: test





date: Sat, 13 Apr 2019 20:27:36 +0200


---

Normally, DNS logs contain a limited amount of different dns queries for a single domain. This rule detects a high amount of queries for a single domain, which can be an indicator that DNS is used to transfer data.

<!--more-->


## Known false-positives

* Valid software, which uses dns for transferring data



## References

* https://zeltser.com/c2-dns-tunneling/
* https://patrick-bareiss.com/detect-c2-traffic-over-dns-using-sigma/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_dns_c2_detection.yml))
```yaml
title: Possible DNS Tunneling
id: 1ec4b281-aa65-46a2-bdae-5fd830ed914e
status: test
description: Normally, DNS logs contain a limited amount of different dns queries for a single domain. This rule detects a high amount of queries for a single domain, which can be an indicator that DNS is used to transfer data.
author: Patrick Bareiss
references:
  - https://zeltser.com/c2-dns-tunneling/
  - https://patrick-bareiss.com/detect-c2-traffic-over-dns-using-sigma/
date: 2019/04/07
modified: 2021/11/27
logsource:
  category: dns
detection:
  selection:
    parent_domain: '*'
  condition: selection | count(dns_query) by parent_domain > 1000
falsepositives:
  - Valid software, which uses dns for transferring data
level: high
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003

```
