---
title: "Query to GoToAssist Remote Access Software Domain"
aliases:
  - "/rule/7c4cf8e0-1362-48b2-a512-b606d2065d7d"




status: experimental





date: Sun, 13 Feb 2022 11:04:00 +0100


---

An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_gotoopener.yml))
```yaml
title: Query to GoToAssist Remote Access Software Domain
id: 7c4cf8e0-1362-48b2-a512-b606d2065d7d
status: experimental
description: |
  An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
  These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
  Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land) 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-4---gotoassist-files-detected-test-on-windows
author: frack113
date: 2022/02/13
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|endswith: '.getgo.com'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
