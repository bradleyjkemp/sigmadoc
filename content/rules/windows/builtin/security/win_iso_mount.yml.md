---
title: "ISO Image Mount"
aliases:
  - "/rule/0248a7bc-8a9a-4cd8-a57e-3ae8e073a073"


tags:
  - attack.initial_access
  - attack.t1566.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the mount of ISO images on an endpoint

<!--more-->


## Known false-positives

* Software installation ISO files



## References

* https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
* https://www.proofpoint.com/us/blog/threat-insight/threat-actor-profile-ta2719-uses-colorful-lures-deliver-rats-local-languages
* https://twitter.com/MsftSecIntel/status/1257324139515269121


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_iso_mount.yml))
```yaml
title: ISO Image Mount
id: 0248a7bc-8a9a-4cd8-a57e-3ae8e073a073
description: Detects the mount of ISO images on an endpoint
status: experimental
date: 2021/05/29
modified: 2021/11/20
author: Syed Hasan (@syedhasan009)
references: 
    - https://www.trendmicro.com/vinfo/hk-en/security/news/cybercrime-and-digital-threats/malicious-spam-campaign-uses-iso-image-files-to-deliver-lokibot-and-nanocore
    - https://www.proofpoint.com/us/blog/threat-insight/threat-actor-profile-ta2719-uses-colorful-lures-deliver-rats-local-languages
    - https://twitter.com/MsftSecIntel/status/1257324139515269121
tags:
    - attack.initial_access
    - attack.t1566.001
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Removable Storage" must be configured for Success/Failure'
detection:
    selection: 
        EventID: 4663
        ObjectServer: 'Security'
        ObjectType: 'File'
        ObjectName: '\Device\CdRom*'
    filter:
        ObjectName: '\Device\CdRom0\setup.exe'
    condition: selection and not filter
falsepositives:
    - Software installation ISO files
level: medium

```
