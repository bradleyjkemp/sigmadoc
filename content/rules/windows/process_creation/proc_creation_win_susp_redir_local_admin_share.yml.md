---
title: "Suspicious Redirection to Local Admin Share"
aliases:
  - "/rule/ab9e3b40-0c85-4ba1-aede-455d226fd124"
ruleid: ab9e3b40-0c85-4ba1-aede-455d226fd124



status: experimental





date: Sun, 16 Jan 2022 17:40:50 +0100


---

Detects a suspicious output redirection to the local admins share as often found in malicious scripts or hacktool stagers

<!--more-->


## Known false-positives

* unknown



## References

* https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_redir_local_admin_share.yml))
```yaml
title: Suspicious Redirection to Local Admin Share
id: ab9e3b40-0c85-4ba1-aede-455d226fd124
status: experimental
description: Detects a suspicious output redirection to the local admins share as often found in malicious scripts or hacktool stagers
author: Florian Roth
date: 2022/01/16
modified: 2022/02/01
references:
    - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 
            - '> \\\\127.0.0.1\\admin$'
            - '> \\\\localhost\\admin$'
    condition: selection
falsepositives:
    - unknown
level: high

```
