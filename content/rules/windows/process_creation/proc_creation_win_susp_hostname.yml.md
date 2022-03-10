---
title: "Suspicious Execution of Hostname"
aliases:
  - "/rule/7be5fb68-f9ef-476d-8b51-0256ebece19e"


tags:
  - attack.discovery
  - attack.t1082



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Use of hostname to get information

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/hostname


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_hostname.yml))
```yaml
title: Suspicious Execution of Hostname 
id: 7be5fb68-f9ef-476d-8b51-0256ebece19e
status: experimental
description: Use of hostname to get information
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md#atomic-test-6---hostname-discovery-windows
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/hostname
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \HOSTNAME.EXE
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1082

```
