---
title: "Silenttrinity Stager Msbuild Activity"
aliases:
  - "/rule/50e54b8d-ad73-43f8-96a1-5191685b17a4"


tags:
  - attack.execution
  - attack.t1127.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a possible remote connections to Silenttrinity c2

<!--more-->


## Known false-positives

* unknown



## References

* https://www.blackhillsinfosec.com/my-first-joyride-with-silenttrinity/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_silenttrinity_stager_msbuild_activity.yml))
```yaml
title: Silenttrinity Stager Msbuild Activity
id: 50e54b8d-ad73-43f8-96a1-5191685b17a4
status: test
description: Detects a possible remote connections to Silenttrinity c2
author: Kiran kumar s, oscd.community
references:
  - https://www.blackhillsinfosec.com/my-first-joyride-with-silenttrinity/
date: 2020/10/11
modified: 2021/11/27
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith: '\msbuild.exe'
  filter:
    DestinationPort:
      - '80'
      - '443'
    Initiated: 'true'
  condition: selection and filter
falsepositives:
  - unknown
level: high
tags:
  - attack.execution
  - attack.t1127.001

```
