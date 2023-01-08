---
title: "Run Whoami Showing Privileges"
aliases:
  - "/rule/97a80ec7-0e2f-4d05-9ef4-65760e634f6b"
ruleid: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b

tags:
  - attack.privilege_escalation
  - attack.discovery
  - attack.t1033



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt.

<!--more-->


## Known false-positives

* Administrative activity (rare lookups on current privileges)



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_whoami_priv.yml))
```yaml
title: Run Whoami Showing Privileges
id: 97a80ec7-0e2f-4d05-9ef4-65760e634f6b
status: experimental
description: Detects a whoami.exe executed with the /priv command line flag instructing the tool to show all current user privieleges. This is often used after a privilege escalation attempt. 
references:
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/whoami
author: Florian Roth
date: 2021/05/05
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
        CommandLine|contains: '/priv'
    condition: selection
falsepositives:
    - Administrative activity (rare lookups on current privileges)
level: high

```
