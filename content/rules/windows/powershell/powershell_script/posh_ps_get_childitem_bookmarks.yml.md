---
title: "Automated Collection Bookmarks Using Get-ChildItem PowerShell"
aliases:
  - "/rule/e0565f5d-d420-4e02-8a68-ac00d864f9cf"


tags:
  - attack.discovery
  - attack.t1217



status: experimental





date: Mon, 13 Dec 2021 11:02:33 +0100


---

Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
internal network resources such as servers, tools/dashboards, or other related infrastructure.


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_get_childitem_bookmarks.yml))
```yaml
title: Automated Collection Bookmarks Using Get-ChildItem PowerShell
id: e0565f5d-d420-4e02-8a68-ac00d864f9cf
status: experimental
author: frack113
date: 2021/12/13
description: |
    Adversaries may enumerate browser bookmarks to learn more about compromised hosts.
    Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about
    internal network resources such as servers, tools/dashboards, or other related infrastructure.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Get-ChildItem'
            - ' -Recurse '
            - ' -Path '
            - ' -Filter Bookmarks' 
            - ' -ErrorAction SilentlyContinue'
            - ' -Force'
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1217


```
