---
title: "Suspicious Encoded Scripts in a WMI Consumer"
aliases:
  - "/rule/83844185-1c5b-45bc-bcf3-b5bf3084ca5b"
ruleid: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b

tags:
  - attack.execution
  - attack.t1047
  - attack.persistence
  - attack.t1546.003



status: experimental





date: Wed, 1 Sep 2021 13:57:36 +0200


---

Detects suspicious encoded payloads in WMI Event Consumers

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/RiccardoAncarani/LiquidSnake


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/wmi_event/sysmon_wmi_susp_encoded_scripts.yml))
```yaml
title: Suspicious Encoded Scripts in a WMI Consumer
id: 83844185-1c5b-45bc-bcf3-b5bf3084ca5b
status: experimental
description: Detects suspicious encoded payloads in WMI Event Consumers
author: Florian Roth
references:
    - https://github.com/RiccardoAncarani/LiquidSnake
date: 2021/09/01
tags:
    - attack.execution
    - attack.t1047
    - attack.persistence
    - attack.t1546.003
logsource:
    product: windows
    category: wmi_event
detection:
    selection_destination:
        Destination|base64offset|contains:
            - 'WriteProcessMemory'
            - 'This program cannot be run in DOS mode'
            - 'This program must be run under Win32'
    condition: selection_destination
fields:
    - User
    - Operation
falsepositives:
    - Unknown
level: high

```
