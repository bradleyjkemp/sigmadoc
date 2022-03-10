---
title: "Suspicious Windows ANONYMOUS LOGON Local Account Created"
aliases:
  - "/rule/1bbf25b9-8038-4154-a50b-118f2a32be27"


tags:
  - attack.persistence
  - attack.t1136.001
  - attack.t1136.002



status: experimental





date: Thu, 31 Oct 2019 21:56:30 +1100


---

Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/SBousseaden/status/1189469425482829824


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_local_anon_logon_created.yml))
```yaml
title: Suspicious Windows ANONYMOUS LOGON Local Account Created
id: 1bbf25b9-8038-4154-a50b-118f2a32be27
status: experimental
description: Detects the creation of suspicious accounts similar to ANONYMOUS LOGON, such as using additional spaces. Created as an covering detection for exclusion of Logon Type 3 from ANONYMOUS LOGON accounts.
references:
    - https://twitter.com/SBousseaden/status/1189469425482829824
author: James Pemberton / @4A616D6573
date: 2019/10/31
modified: 2021/07/06
tags:
    - attack.persistence
    - attack.t1136.001
    - attack.t1136.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        SamAccountName|contains|all: 
            - 'ANONYMOUS'
            - 'LOGON'
    condition: selection
falsepositives:
    - Unknown
level: high

```
