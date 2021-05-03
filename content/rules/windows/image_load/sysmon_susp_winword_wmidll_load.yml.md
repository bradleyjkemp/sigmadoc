---
title: "Windows Mangement Instrumentation DLL Loaded Via Microsoft Word"
aliases:
  - "/rule/a457f232-7df9-491d-898f-b5aabd2cbe2f"

tags:
  - attack.execution
  - attack.t1047



date: Sun, 29 Dec 2019 23:14:29 +0900


---

Detects DLL's Loaded Via Word Containing VBA Macros Executing WMI Commands

<!--more-->


## Known false-positives

* Possible. Requires further testing.



## References

* https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
* https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/
* https://media.cert.europa.eu/static/SecurityAdvisories/2019/CERT-EU-SA2019-021.pdf


## Raw rule
```yaml
title: Windows Mangement Instrumentation DLL Loaded Via Microsoft Word
id: a457f232-7df9-491d-898f-b5aabd2cbe2f
status: experimental
description: Detects DLL's Loaded Via Word Containing VBA Macros Executing WMI Commands
references:
    - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
    - https://www.carbonblack.com/2019/04/24/cb-tau-threat-intelligence-notification-emotet-utilizing-wmi-to-launch-powershell-encoded-code/
    - https://media.cert.europa.eu/static/SecurityAdvisories/2019/CERT-EU-SA2019-021.pdf
author: Michael R. (@nahamike01)
date: 2019/12/26
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image:
            - '*\winword.exe'
            - '*\powerpnt.exe'
            - '*\excel.exe'
            - '*\outlook.exe'
        ImageLoaded:
            - '*\wmiutils.dll'
            - '*\wbemcomn.dll'
            - '*\wbemprox.dll'
            - '*\wbemdisp.dll'
            - '*\wbemsvc.dll'
    condition: selection
falsepositives:
    - Possible. Requires further testing.
level: high

```
