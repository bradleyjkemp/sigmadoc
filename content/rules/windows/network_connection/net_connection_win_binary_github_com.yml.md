---
title: "Microsoft Binary Github Communication"
aliases:
  - "/rule/635dbb88-67b3-4b41-9ea5-a3af2dd88153"
ruleid: 635dbb88-67b3-4b41-9ea5-a3af2dd88153

tags:
  - attack.lateral_movement
  - attack.t1105
  - attack.exfiltration
  - attack.t1567.001



status: test





date: Thu, 24 Aug 2017 18:27:22 +0200


---

Detects an executable in the Windows folder accessing github.com

<!--more-->


## Known false-positives

* Unknown
* @subTee in your network



## References

* https://twitter.com/M_haggis/status/900741347035889665
* https://twitter.com/M_haggis/status/1032799638213066752
* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/exfil/Invoke-ExfilDataToGitHub.ps1


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_binary_github_com.yml))
```yaml
title: Microsoft Binary Github Communication
id: 635dbb88-67b3-4b41-9ea5-a3af2dd88153
status: test
description: Detects an executable in the Windows folder accessing github.com
author: Michael Haag (idea), Florian Roth (rule)
references:
  - https://twitter.com/M_haggis/status/900741347035889665
  - https://twitter.com/M_haggis/status/1032799638213066752
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/exfil/Invoke-ExfilDataToGitHub.ps1
date: 2017/08/24
modified: 2021/11/27
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationHostname|endswith:
      - '.github.com'
      - '.githubusercontent.com'
    Image|startswith: 'C:\Windows\'
  condition: selection
falsepositives:
  - 'Unknown'
  - '@subTee in your network'
level: high
tags:
  - attack.lateral_movement
  - attack.t1105
  - attack.exfiltration
  - attack.t1567.001

```
