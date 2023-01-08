---
title: "Conti Ransomware Execution"
aliases:
  - "/rule/689308fc-cfba-4f72-9897-796c1dc61487"
ruleid: 689308fc-cfba-4f72-9897-796c1dc61487

tags:
  - attack.impact
  - attack.s0575
  - attack.t1486



status: experimental





date: Tue, 12 Oct 2021 20:57:12 +0200


---

Conti ransomware command line ioc

<!--more-->


## Known false-positives

* Unknown should be low



## References

* https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
* https://twitter.com/VK_Intel/status/1447795359900704769?t=Xz7vaLTvaaCZ5kHoZa6gMw&s=19


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_conti_cmd_ransomware.yml))
```yaml
title: Conti Ransomware Execution
id: 689308fc-cfba-4f72-9897-796c1dc61487
status: experimental
author: frack113
date: 2021/10/12
description: Conti ransomware command line ioc
references:
    - https://news.sophos.com/en-us/2021/09/03/conti-affiliates-use-proxyshell-exchange-exploit-in-ransomware-attacks/
    - https://twitter.com/VK_Intel/status/1447795359900704769?t=Xz7vaLTvaaCZ5kHoZa6gMw&s=19
tags:
    - attack.impact
    - attack.s0575
    - attack.t1486
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-m '
            - '-net '
            - '-size ' #size 10 in references
            - '-nomutex '
            - '-p \\'
            - '$'
    condition: selection 
falsepositives:
    - Unknown should be low
level: critical

```
