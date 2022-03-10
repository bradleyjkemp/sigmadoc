---
title: "Active Directory Parsing DLL Loaded Via Office Applications"
aliases:
  - "/rule/a2a3b925-7bb0-433b-b508-db9003263cc4"


tags:
  - attack.execution
  - attack.t1204.002



status: test





date: Wed, 19 Feb 2020 10:13:44 -0500


---

Detects DSParse DLL being loaded by an Office Product

<!--more-->


## Known false-positives

* Alerts on legitimate macro usage as well, will need to filter as appropriate



## References

* https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_office_dsparse_dll_load.yml))
```yaml
title: Active Directory Parsing DLL Loaded Via Office Applications
id: a2a3b925-7bb0-433b-b508-db9003263cc4
status: test
description: Detects DSParse DLL being loaded by an Office Product
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
    ImageLoaded|contains:
      - '\dsparse.dll'
  condition: selection
falsepositives:
  - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high
tags:
  - attack.execution
  - attack.t1204.002

```
