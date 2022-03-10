---
title: "Cred Dump-Tools Named Pipes"
aliases:
  - "/rule/961d0ba2-3eea-4303-a930-2cf78bbfcc5e"


tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Detects well-known credential dumping tools execution via specific named pipes

<!--more-->


## Known false-positives

* Legitimate Administrator using tool for password recovery



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_cred_dump_tools_named_pipes.yml))
```yaml
title: Cred Dump-Tools Named Pipes
id: 961d0ba2-3eea-4303-a930-2cf78bbfcc5e
status: test
description: Detects well-known credential dumping tools execution via specific named pipes
author: Teymur Kheirkhabarov, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/11/01
modified: 2021/11/27
logsource:
  product: windows
  category: pipe_created
  definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
  selection:
    PipeName|contains:
      - '\lsadump'
      - '\cachedump'
      - '\wceservicepipe'
  condition: selection
falsepositives:
  - Legitimate Administrator using tool for password recovery
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005

```