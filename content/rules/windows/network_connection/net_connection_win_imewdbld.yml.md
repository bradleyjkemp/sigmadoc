---
title: "Download a File with IMEWDBLD.exe"
aliases:
  - "/rule/8d7e392e-9b28-49e1-831d-5949c6281228"


tags:
  - attack.command_and_control
  - attack.t1105



status: experimental





date: Sun, 23 Jan 2022 11:37:01 +0100


---

Use IMEWDBLD.exe (built-in to windows) to download a file

<!--more-->


## Known false-positives

* Legitimate script



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
* https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_imewdbld.yml))
```yaml
title: Download a File with IMEWDBLD.exe
id: 8d7e392e-9b28-49e1-831d-5949c6281228
status: experimental
description: Use IMEWDBLD.exe (built-in to windows) to download a file
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md#atomic-test-10---windows---powershell-download
  - https://lolbas-project.github.io/lolbas/Binaries/IMEWDBLD/
date: 2022/01/22
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    Image|endswith: '\IMEWDBLD.exe'
  condition: selection
falsepositives:
  - Legitimate script
level: high
tags:
    - attack.command_and_control
    - attack.t1105
```
