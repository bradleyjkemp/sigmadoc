---
title: "GAC DLL Loaded Via Office Applications"
aliases:
  - "/rule/90217a70-13fc-48e4-b3db-0d836c5824ac"
ruleid: 90217a70-13fc-48e4-b3db-0d836c5824ac

tags:
  - attack.execution
  - attack.t1204.002



status: test





date: Wed, 19 Feb 2020 10:13:44 -0500


---

Detects any GAC DLL being loaded by an Office Product

<!--more-->


## Known false-positives

* Alerts on legitimate macro usage as well, will need to filter as appropriate



## References

* https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_office_dotnet_gac_dll_load.yml))
```yaml
title: GAC DLL Loaded Via Office Applications
id: 90217a70-13fc-48e4-b3db-0d836c5824ac
status: test
description: Detects any GAC DLL being loaded by an Office Product
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
    ImageLoaded|startswith:
      - 'C:\Windows\Microsoft.NET\assembly\GAC_MSIL'
  condition: selection
falsepositives:
  - Alerts on legitimate macro usage as well, will need to filter as appropriate
level: high
tags:
  - attack.execution
  - attack.t1204.002

```
