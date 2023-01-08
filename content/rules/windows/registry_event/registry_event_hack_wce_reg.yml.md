---
title: "Windows Credential Editor Registry"
aliases:
  - "/rule/a6b33c02-8305-488f-8585-03cb2a7763f2"
ruleid: a6b33c02-8305-488f-8585-03cb2a7763f2

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0005



status: test





date: Tue, 31 Dec 2019 09:27:38 +0100


---

Detects the use of Windows Credential Editor (WCE)

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.ampliasecurity.com/research/windows-credentials-editor/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_hack_wce_reg.yml))
```yaml
title: Windows Credential Editor Registry
id: a6b33c02-8305-488f-8585-03cb2a7763f2
status: test
description: Detects the use of Windows Credential Editor (WCE)
author: Florian Roth
references:
  - https://www.ampliasecurity.com/research/windows-credentials-editor/
date: 2019/12/31
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|contains: Services\WCESERVICE\Start
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.s0005

```
