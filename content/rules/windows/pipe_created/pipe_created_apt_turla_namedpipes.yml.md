---
title: "Turla Group Named Pipes"
aliases:
  - "/rule/739915e4-1e70-4778-8b8a-17db02f66db1"


tags:
  - attack.g0010
  - attack.execution
  - attack.t1106



status: test





date: Mon, 6 Nov 2017 14:22:09 +0100


---

Detects a named pipe used by Turla group samples

<!--more-->


## Known false-positives

* Unknown



## References

* Internal Research
* https://attack.mitre.org/groups/G0010/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_apt_turla_namedpipes.yml))
```yaml
title: Turla Group Named Pipes
id: 739915e4-1e70-4778-8b8a-17db02f66db1
status: test
description: Detects a named pipe used by Turla group samples
author: Markus Neis
references:
  - Internal Research
  - https://attack.mitre.org/groups/G0010/
date: 2017/11/06
modified: 2021/11/27
logsource:
  product: windows
  category: pipe_created
  definition: 'Note that you have to configure logging for Named Pipe Events in Sysmon config (Event ID 17 and Event ID 18). The basic configuration is in popular sysmon configuration (https://github.com/SwiftOnSecurity/sysmon-config), but it is worth verifying. You can also use other repo, e.g. https://github.com/Neo23x0/sysmon-config, https://github.com/olafhartong/sysmon-modular. How to test detection? You can check powershell script from this site https://svch0st.medium.com/guide-to-named-pipes-and-hunting-for-cobalt-strike-pipes-dc46b2c5f575'
detection:
  selection:
    PipeName:
      - '\atctl'       # https://www.virustotal.com/#/file/a4ddb2664a6c87a1d3c5da5a5a32a5df9a0b0c8f2e951811bd1ec1d44d42ccf1/detection
      - '\userpipe'       # ruag apt case
      - '\iehelper'       # ruag apt case
      - '\sdlrpc'       # project cobra https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
      - '\comnap'       # https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra
            # - '\rpc'  # may cause too many false positives : http://kb.palisade.com/index.php?pg=kb.page&id=483
  condition: selection
falsepositives:
  - Unknown
level: critical
tags:
  - attack.g0010
  - attack.execution
  - attack.t1106

```