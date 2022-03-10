---
title: "Notepad Making Network Connection"
aliases:
  - "/rule/e81528db-fc02-45e8-8e98-4e84aba1f10b"


tags:
  - attack.command_and_control
  - attack.execution
  - attack.defense_evasion
  - attack.t1055



status: test





date: Thu, 14 May 2020 18:08:30 +0700


---

Detects suspicious network connection by Notepad

<!--more-->


## Known false-positives

* None observed so far



## References

* https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf
* https://blog.cobaltstrike.com/2013/08/08/why-is-notepad-exe-connecting-to-the-internet/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_notepad_network_connection.yml))
```yaml
title: Notepad Making Network Connection
id: e81528db-fc02-45e8-8e98-4e84aba1f10b
status: test
description: Detects suspicious network connection by Notepad
author: EagleEye Team
references:
  - https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf
  - https://blog.cobaltstrike.com/2013/08/08/why-is-notepad-exe-connecting-to-the-internet/
date: 2020/05/14
modified: 2021/11/27
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith: '\notepad.exe'
  filter:
    DestinationPort: '9100'
  condition: selection and not filter
falsepositives:
  - None observed so far
level: high
tags:
  - attack.command_and_control
  - attack.execution
  - attack.defense_evasion
  - attack.t1055

```
