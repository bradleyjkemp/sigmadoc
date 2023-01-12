---
title: "VBA DLL Loaded Via Microsoft Word"
aliases:
  - "/rule/e6ce8457-68b1-485b-9bdd-3c2b5d679aa9"
ruleid: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9

tags:
  - attack.execution
  - attack.t1204.002



status: test





date: Wed, 19 Feb 2020 10:13:44 -0500


---

Detects DLL's Loaded Via Word Containing VBA Macros

<!--more-->


## Known false-positives

* Alerts on legitimate macro usage as well, will need to filter as appropriate



## References

* https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_winword_vbadll_load.yml))
```yaml
title: VBA DLL Loaded Via Microsoft Word
id: e6ce8457-68b1-485b-9bdd-3c2b5d679aa9
status: test
description: Detects DLL's Loaded Via Word Containing VBA Macros
author: Antonlovesdnb
references:
  - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
date: 2020/02/19
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith:
      - '\winword.exe'
      - '\powerpnt.exe'
      - '\excel.exe'
      - '\outlook.exe'
    ImageLoaded|endswith:
      - '\VBE7.DLL'
      - '\VBEUI.DLL'
      - '\VBE7INTL.DLL'
  condition: selection
falsepositives:
  - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high
tags:
  - attack.execution
  - attack.t1204.002

```