---
title: "Recon Activity with NLTEST"
aliases:
  - "/rule/5cc90652-4cbd-4241-aa3b-4b462fa5a248"


tags:
  - attack.discovery
  - attack.t1016
  - attack.t1482



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects nltest commands that can be used for information discovery

<!--more-->


## Known false-positives

* Legitimate administration use but user must be check out



## References

* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
* https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
* https://attack.mitre.org/techniques/T1482/
* https://attack.mitre.org/techniques/T1016/
* https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_nltest_recon.yml))
```yaml
title: Recon Activity with NLTEST
id: 5cc90652-4cbd-4241-aa3b-4b462fa5a248
description: Detects nltest commands that can be used for information discovery
references:
  - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
  - https://thedfirreport.com/2021/08/16/trickbot-leads-up-to-fake-1password-installation/
  - https://attack.mitre.org/techniques/T1482/
  - https://attack.mitre.org/techniques/T1016/
  - https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters
status: experimental
author: Craig Young, oscd.community, Georg Lauenstein
date: 2021/07/24
modified: 2021/08/19
tags:
  - attack.discovery
  - attack.t1016
  - attack.t1482
logsource:
  category: process_creation
  product: windows
detection:
    selection_nltest:
        Image|endswith: '\nltest.exe'
    selection_recon1:
        CommandLine|contains|all:
            - '/server'
            - '/query'
    selection_recon2:
        CommandLine|contains:
            - '/dclist:'
            - '/parentdomain'
            - '/domain_trusts'
            - '/trusted_domains'
            - '/user'
    condition: selection_nltest and (selection_recon1 or selection_recon2)
falsepositives:
    - Legitimate administration use but user must be check out
level: medium
fields:
    - Image
    - User
    - CommandLine
    - ParentCommandLine

```