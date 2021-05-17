---
title: "Possible Impacket SecretDump Remote Activity - Zeek"
aliases:
  - "/rule/92dae1ed-1c9d-4eff-a567-33acbd95b00e"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.003





level: high



date: Sat, 2 May 2020 07:27:51 -0400


---

Detect AD credential dumping using impacket secretdump HKTL. Based on the SIGMA rules/windows/builtin/win_impacket_secretdump.yml

<!--more-->


## Known false-positives

* unknown



## References

* https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html


## Raw rule
```yaml
title: Possible Impacket SecretDump Remote Activity - Zeek
id: 92dae1ed-1c9d-4eff-a567-33acbd95b00e
description: 'Detect AD credential dumping using impacket secretdump HKTL. Based on the SIGMA rules/windows/builtin/win_impacket_secretdump.yml'
author: 'Samir Bousseaden, @neu5ron'
date: 2020/03/19
references:
    - https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
tags:
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.003
logsource:
    product: zeek
    service: smb_files
detection:
    selection:
        path: '\\*ADMIN$'
        name: '*SYSTEM32\\*.tmp'
    condition: selection
falsepositives:
    - 'unknown'
level: high

```
