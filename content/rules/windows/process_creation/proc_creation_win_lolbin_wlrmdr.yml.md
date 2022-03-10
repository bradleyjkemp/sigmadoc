---
title: "Wlrmdr Lolbin Use as Laucher"
aliases:
  - "/rule/9cfc00b6-bfb7-49ce-9781-ef78503154bb"


tags:
  - attack.defense_evasion



status: experimental





date: Wed, 16 Feb 2022 19:53:46 +0100


---

Detects use of Wlrmdr.exe in which the -u parameter is passed to ShellExecute

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/0gtweet/status/1493963591745220608?s=20&t=xUg9DsZhJy1q9bPTUWgeIQ


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbin_wlrmdr.yml))
```yaml
title: Wlrmdr Lolbin Use as Laucher
id: 9cfc00b6-bfb7-49ce-9781-ef78503154bb
status: experimental
description: Detects use of Wlrmdr.exe in which the -u parameter is passed to ShellExecute
references:
    - https://twitter.com/0gtweet/status/1493963591745220608?s=20&t=xUg9DsZhJy1q9bPTUWgeIQ
author: frack113
date: 2022/02/16
modified: 2022/02/21
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: wlrmdr.exe
        CommandLine|contains|all:
            - '-s '
            - '-f '
            - '-t '
            - '-m '
            - '-a '
            - '-u '
    filter:
        ParentImage: 'C:\Windows\System32\winlogon.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
tags:
    - attack.defense_evasion

```
