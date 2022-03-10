---
title: "FoggyWeb Backdoor DLL Loading"
aliases:
  - "/rule/640dc51c-7713-4faa-8a0e-e7c0d9d4654c"


tags:
  - attack.resource_development
  - attack.t1587



status: experimental





date: Mon, 27 Sep 2021 22:28:25 +0200


---

Detects DLL image load activity as used by FoggyWeb backdoor loader

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.microsoft.com/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_foggyweb_nobelium.yml))
```yaml
title: FoggyWeb Backdoor DLL Loading
id: 640dc51c-7713-4faa-8a0e-e7c0d9d4654c
status: experimental
description: Detects DLL image load activity as used by FoggyWeb backdoor loader
references:
    - https://www.microsoft.com/security/blog/2021/09/27/foggyweb-targeted-nobelium-malware-leads-to-persistent-backdoor/
author: Florian Roth
date: 2021/09/27
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image: C:\Windows\ADFS\version.dll
    condition: selection
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.resource_development
    - attack.t1587

```
