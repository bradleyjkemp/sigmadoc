---
title: "Query Tor Onion Address"
aliases:
  - "/rule/b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544"
ruleid: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544

tags:
  - attack.command_and_control
  - attack.t1090.003



status: experimental





date: Sun, 20 Feb 2022 11:26:13 +0100


---

Detects DNS resolution of an .onion address related to Tor routing networks

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_tor_onion.yml))
```yaml
title: Query Tor Onion Address
id: b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544
status: experimental
description: Detects DNS resolution of an .onion address related to Tor routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022/02/20
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: '.onion'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.command_and_control
    - attack.t1090.003

```
