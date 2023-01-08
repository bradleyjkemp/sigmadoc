---
title: "AppInstaller Attempts From URL by DNS"
aliases:
  - "/rule/7cff77e1-9663-46a3-8260-17f2e1aa9d0a"
ruleid: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a

tags:
  - attack.command_and_control
  - attack.t1105



status: experimental





date: Wed, 24 Nov 2021 19:17:00 +0100


---

AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/notwhickey/status/1333900137232523264
* https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_lobas_appinstaller.yml))
```yaml
title: AppInstaller Attempts From URL by DNS
id: 7cff77e1-9663-46a3-8260-17f2e1aa9d0a
description: AppInstaller.exe is spawned by the default handler for the URI, it attempts to load/install a package from the URL
status: experimental
date: 2021/11/24
author: frack113
tags:
    - attack.command_and_control
    - attack.t1105
references:
    - https://twitter.com/notwhickey/status/1333900137232523264
    - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        Image|startswith: C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_
        Image|endswith: \AppInstaller.exe
    condition: selection
falsepositives:
    - Unknown
level: medium
```
