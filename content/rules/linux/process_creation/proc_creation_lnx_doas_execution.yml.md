---
title: "Linux Doas Tool Execution"
aliases:
  - "/rule/067d8238-7127-451c-a9ec-fa78045b618b"


tags:
  - attack.privilege_escalation
  - attack.t1548



status: stable





date: Thu, 20 Jan 2022 09:46:17 +0700


---

Detects the doas tool execution in linux host platform.

<!--more-->


## Known false-positives

* Unlikely



## References

* https://research.splunk.com/endpoint/linux_doas_tool_execution/
* https://www.makeuseof.com/how-to-install-and-use-doas/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_doas_execution.yml))
```yaml
title: Linux Doas Tool Execution
id: 067d8238-7127-451c-a9ec-fa78045b618b
status: stable
description: Detects the doas tool execution in linux host platform.
references:
    - https://research.splunk.com/endpoint/linux_doas_tool_execution/
    - https://www.makeuseof.com/how-to-install-and-use-doas/
author: Sittikorn S, Teoderick Contreras
date: 2022/01/20
tags:
    - attack.privilege_escalation
    - attack.t1548
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/doas'
    condition: selection
falsepositives:
    - Unlikely
level: low

```
