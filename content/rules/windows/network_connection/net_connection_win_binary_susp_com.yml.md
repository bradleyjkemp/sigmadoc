---
title: "Microsoft Binary Suspicious Communication Endpoint"
aliases:
  - "/rule/e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97"


tags:
  - attack.lateral_movement
  - attack.t1105



status: test





date: Thu, 24 Aug 2017 18:27:22 +0200


---

Detects an executable in the Windows folder accessing suspicious domains

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/M_haggis/status/900741347035889665
* https://twitter.com/M_haggis/status/1032799638213066752


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_binary_susp_com.yml))
```yaml
title: Microsoft Binary Suspicious Communication Endpoint
id: e0f8ab85-0ac9-423b-a73a-81b3c7b1aa97
status: test
description: Detects an executable in the Windows folder accessing suspicious domains
author: Florian Roth
references:
  - https://twitter.com/M_haggis/status/900741347035889665
  - https://twitter.com/M_haggis/status/1032799638213066752
date: 2018/08/30
modified: 2021/11/27
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    Initiated: 'true'
    DestinationHostname|endswith:
      - 'dl.dropboxusercontent.com'
      - '.pastebin.com'
      - '.githubusercontent.com'       # includes both gists and github repositories
    Image|startswith: 'C:\Windows\'
  condition: selection
falsepositives:
  - 'Unknown'
level: high
tags:
  - attack.lateral_movement
  - attack.t1105

```
