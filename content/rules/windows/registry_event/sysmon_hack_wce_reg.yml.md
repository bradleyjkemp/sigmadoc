---
title: "Windows Credential Editor Registry"
aliases:
  - "/rule/a6b33c02-8305-488f-8585-03cb2a7763f2"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
  - attack.s0005



date: Tue, 31 Dec 2019 09:27:38 +0100


---

Detects the use of Windows Credential Editor (WCE)

<!--more-->


## Known false-positives

* Another service that uses a single -s command line switch



## References

* https://www.ampliasecurity.com/research/windows-credentials-editor/


## Raw rule
```yaml
title: Windows Credential Editor Registry
id: a6b33c02-8305-488f-8585-03cb2a7763f2
description: Detects the use of Windows Credential Editor (WCE)
author: Florian Roth
references:
    - https://www.ampliasecurity.com/research/windows-credentials-editor/
date: 2019/12/31
modified: 2020/09/06
tags:
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.001
    - attack.s0005
logsource:
    category: registry_event
    product: windows
detection:
    selection:       
        TargetObject|contains: Services\WCESERVICE\Start
    condition: selection
falsepositives:
    - 'Another service that uses a single -s command line switch'
level: critical
```
