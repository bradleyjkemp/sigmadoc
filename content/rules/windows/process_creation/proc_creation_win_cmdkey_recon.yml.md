---
title: "Cmdkey Cached Credentials Recon"
aliases:
  - "/rule/07f8bdc2-c9b3-472a-9817-5a670b872f53"
ruleid: 07f8bdc2-c9b3-472a-9817-5a670b872f53

tags:
  - attack.credential_access
  - attack.t1003.005



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects usage of cmdkey to look for cached credentials

<!--more-->


## Known false-positives

* Legitimate administrative tasks



## References

* https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
* https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cmdkey_recon.yml))
```yaml
title: Cmdkey Cached Credentials Recon
id: 07f8bdc2-c9b3-472a-9817-5a670b872f53
status: experimental
description: Detects usage of cmdkey to look for cached credentials
references:
    - https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
    - https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx
author: jmallette
date: 2019/01/16
modified: 2021/07/07
tags:
    - attack.credential_access
    - attack.t1003.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cmdkey.exe'
        CommandLine|contains: ' /list'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - User
falsepositives:
    - Legitimate administrative tasks
level: medium

```
