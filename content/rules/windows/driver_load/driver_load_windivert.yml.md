---
title: "WinDivert Driver Load"
aliases:
  - "/rule/679085d5-f427-4484-9f58-1dc30a7c426d"
ruleid: 679085d5-f427-4484-9f58-1dc30a7c426d

tags:
  - attack.collection
  - attack.defense_evasion
  - attack.t1599.001
  - attack.t1557.001



status: experimental





date: Fri, 30 Jul 2021 16:54:29 +0200


---

Detects the load of the Windiver driver, a powerful user-mode capture/sniffing/modification/blocking/re-injection package for Windows

<!--more-->


## Known false-positives

* legitimate WinDivert driver usage



## References

* https://reqrypt.org/windivert-doc.html
* https://rastamouse.me/ntlm-relaying-via-cobalt-strike/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/driver_load/driver_load_windivert.yml))
```yaml
title: WinDivert Driver Load
id: 679085d5-f427-4484-9f58-1dc30a7c426d
status: experimental
description: Detects the load of the Windiver driver, a powerful user-mode capture/sniffing/modification/blocking/re-injection package for Windows
author: Florian Roth
date: 2021/07/30
references:
    - https://reqrypt.org/windivert-doc.html
    - https://rastamouse.me/ntlm-relaying-via-cobalt-strike/
tags:
    - attack.collection
    - attack.defense_evasion
    - attack.t1599.001
    - attack.t1557.001
logsource:
    category: driver_load
    product: windows
detection:
    selection:
        ImageLoaded|contains: 
            - '\WinDivert.sys'
            - '\WinDivert64.sys'
    condition: selection
falsepositives:
    - legitimate WinDivert driver usage
level: high

```
