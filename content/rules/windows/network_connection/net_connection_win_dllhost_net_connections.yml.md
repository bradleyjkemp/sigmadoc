---
title: "Dllhost Internet Connection"
aliases:
  - "/rule/cfed2f44-16df-4bf3-833a-79405198b277"


tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution
  - attack.t1559.001



status: test





date: Sat, 4 Nov 2017 14:44:16 +0100


---

Detects Dllhost that communicates with public IP addresses

<!--more-->


## Known false-positives

* Communication to other corporate systems that use IP addresses from public address spaces



## References

* https://github.com/Neo23x0/sigma/blob/master/rules/windows/network_connection/sysmon_rundll32_net_connections.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_dllhost_net_connections.yml))
```yaml
title: Dllhost Internet Connection
id: cfed2f44-16df-4bf3-833a-79405198b277
status: test
description: Detects Dllhost that communicates with public IP addresses
author: bartblaze
references:
  - https://github.com/Neo23x0/sigma/blob/master/rules/windows/network_connection/sysmon_rundll32_net_connections.yml
date: 2020/07/13
modified: 2021/12/07
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Image|endswith: '\dllhost.exe'
    Initiated: 'true'
  filter:
    DestinationIp|startswith:
      - '10.'
      - '192.168.'
      - '172.16.'
      - '172.17.'
      - '172.18.'
      - '172.19.'
      - '172.20.'
      - '172.21.'
      - '172.22.'
      - '172.23.'
      - '172.24.'
      - '172.25.'
      - '172.26.'
      - '172.27.'
      - '172.28.'
      - '172.29.'
      - '172.30.'
      - '172.31.'
  filter2:
    DestinationIp:
      - '0:0:0:0:0:0:0:1'
  condition: selection and not 1 of filter*
falsepositives:
  - Communication to other corporate systems that use IP addresses from public address spaces
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution
  - attack.t1559.001

```
