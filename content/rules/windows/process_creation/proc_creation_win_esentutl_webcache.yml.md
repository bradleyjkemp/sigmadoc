---
title: "Esentutl Steals Browser Information"
aliases:
  - "/rule/6a69f62d-ce75-4b57-8dce-6351eb55b362"
ruleid: 6a69f62d-ce75-4b57-8dce-6351eb55b362

tags:
  - attack.collection
  - attack.t1005



status: experimental





date: Sun, 13 Feb 2022 16:07:28 +0100


---

One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe

<!--more-->


## Known false-positives

* legitimate use



## References

* https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
* https://redcanary.com/threat-detection-report/threats/qbot/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_esentutl_webcache.yml))
```yaml
title: Esentutl Steals Browser Information 
id: 6a69f62d-ce75-4b57-8dce-6351eb55b362
status: experimental
description: One way Qbot steals sensitive information is by extracting browser data from Internet Explorer and Microsoft Edge by using the built-in utility esentutl.exe
references:
    - https://thedfirreport.com/2022/02/07/qbot-likes-to-move-it-move-it/
    - https://redcanary.com/threat-detection-report/threats/qbot/
author: frack113
date: 2022/02/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \esentutl.exe
        CommandLine|contains|all:
            - '/r '
            - '\Windows\WebCache'
    condition: selection
falsepositives:
    - legitimate use
level: medium
tags:
    - attack.collection
    - attack.t1005

```
