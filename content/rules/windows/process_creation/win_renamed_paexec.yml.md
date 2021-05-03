---
title: "Execution of Renamed PaExec"
aliases:
  - "/rule/7b0666ad-3e38-4e3d-9bab-78b06de85f7b"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.003
  - FIN7
  - car.2013-05-009



date: Mon, 8 Apr 2019 08:07:30 -0400


---

Detects execution of renamed paexec via imphash and executable product string

<!--more-->


## Known false-positives

* Unknown imphashes



## References

* sha256=01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc
* https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf


## Raw rule
```yaml
title: Execution of Renamed PaExec
id: 7b0666ad-3e38-4e3d-9bab-78b06de85f7b
status: experimental
description: Detects execution of renamed paexec via imphash and executable product string
references:
    - sha256=01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc
    - https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s05-att&cking-fin7.pdf
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003
    - FIN7
    - car.2013-05-009
date: 2019/04/17
modified: 2020/09/06
author: Jason Lynch 
falsepositives:
    - Unknown imphashes
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Product:
            - '*PAExec*'
    selection2:
        Imphash:
            - 11D40A7B7876288F919AB819CC2D9802
            - 6444f8a34e99b8f7d9647de66aabe516
            - dfd6aa3f7b2b1035b76b718f1ddc689f
            - 1a6cca4d5460b1710a12dea39e4a592c
    filter1:
        Image: '*paexec*'
    condition: (selection1 and selection2) and not filter1

```