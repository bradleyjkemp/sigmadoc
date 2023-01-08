---
title: "Tor Client or Tor Browser Use"
aliases:
  - "/rule/62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c"
ruleid: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c

tags:
  - attack.command_and_control
  - attack.t1090.003



status: experimental





date: Sun, 20 Feb 2022 11:26:13 +0100


---

Detects the use of Tor or Tor-Browser to connect to onion routing networks

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_tor_browser.yml))
```yaml
title: Tor Client or Tor Browser Use
id: 62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c
status: experimental
description: Detects the use of Tor or Tor-Browser to connect to onion routing networks
references:
    - https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
author: frack113
date: 2022/02/20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\tor.exe'
            - '\Tor Browser\Browser\firefox.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.command_and_control
    - attack.t1090.003

```
