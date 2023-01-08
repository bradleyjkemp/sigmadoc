---
title: "WMIC Loading Scripting Libraries"
aliases:
  - "/rule/06ce37c2-61ab-4f05-9ff5-b1a96d18ae32"
ruleid: 06ce37c2-61ab-4f05-9ff5-b1a96d18ae32

tags:
  - attack.defense_evasion
  - attack.t1220



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).

<!--more-->


## Known false-positives

* Apparently, wmic os get lastboottuptime loads vbscript.dll



## References

* https://securitydatasets.com/notebooks/small/windows/05_defense_evasion/SDWIN-201017061100.html
* https://twitter.com/dez_/status/986614411711442944
* https://lolbas-project.github.io/lolbas/Binaries/Wmic/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_wmic_remote_xsl_scripting_dlls.yml))
```yaml
title: WMIC Loading Scripting Libraries
id: 06ce37c2-61ab-4f05-9ff5-b1a96d18ae32
status: test
description: Detects threat actors proxy executing code and bypassing application controls by leveraging wmic and the `/FORMAT` argument switch to download and execute an XSL file (i.e js, vbs, etc).
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://securitydatasets.com/notebooks/small/windows/05_defense_evasion/SDWIN-201017061100.html
  - https://twitter.com/dez_/status/986614411711442944
  - https://lolbas-project.github.io/lolbas/Binaries/Wmic/
date: 2020/10/17
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith: '\wmic.exe'
    ImageLoaded|endswith:
      - '\jscript.dll'
      - '\vbscript.dll'
  condition: selection
falsepositives:
  - Apparently, wmic os get lastboottuptime loads vbscript.dll
level: high
tags:
  - attack.defense_evasion
  - attack.t1220

```
