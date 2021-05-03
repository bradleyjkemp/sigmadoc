---
title: "Mustang Panda Dropper"
aliases:
  - "/rule/2d87d610-d760-45ee-a7e6-7a6f2a65de00"



date: Wed, 30 Oct 2019 18:22:40 +0100


---

Detects specific process parameters as used by Mustang Panda droppers

<!--more-->


## Known false-positives

* Unlikely



## References

* https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/
* https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/
* https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations


## Raw rule
```yaml
title: Mustang Panda Dropper
id: 2d87d610-d760-45ee-a7e6-7a6f2a65de00
status: experimental
description: Detects specific process parameters as used by Mustang Panda droppers
author: Florian Roth
date: 2019/10/30
references:
    - https://app.any.run/tasks/7ca5661d-a67b-43ec-98c1-dd7a8103c256/
    - https://app.any.run/tasks/b12cccf3-1c22-4e28-9d3e-c7a6062f3914/
    - https://www.anomali.com/blog/china-based-apt-mustang-panda-targets-minority-groups-public-and-private-sector-organizations
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: 
            - '*Temp\wtask.exe /create*'
            - '*%windir:~-3,1%%PUBLIC:~-9,1%*'
            - '*/E:vbscript * C:\Users\\*.txt" /F'
            - '*/tn "Security Script *'
            - '*%windir:~-1,1%*'
    selection2:
        Image:
            - '*Temp\winwsh.exe'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: high

```
