---
title: "PsExec Pipes Artifacts"
aliases:
  - "/rule/9e77ed63-2ecf-4c7b-b09d-640834882028"
ruleid: 9e77ed63-2ecf-4c7b-b09d-640834882028

tags:
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detecting use PsExec via Pipe Creation/Access to pipes

<!--more-->


## Known false-positives

* Legitimate Administrator activity



## References

* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_psexec_pipes_artifacts.yml))
```yaml
title: PsExec Pipes Artifacts
id: 9e77ed63-2ecf-4c7b-b09d-640834882028
status: test
description: Detecting use PsExec via Pipe Creation/Access to pipes
author: Nikita Nazarov, oscd.community
references:
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
date: 2020/05/10
modified: 2021/11/27
logsource:
  product: windows
  category: pipe_created
  definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
  selection:
    PipeName|startswith:
      - 'psexec'
      - 'paexec'
      - 'remcom'
      - 'csexec'
  condition: selection
falsepositives:
  - Legitimate Administrator activity
level: medium
tags:
  - attack.lateral_movement
  - attack.t1021.002

```