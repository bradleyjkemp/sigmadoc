---
title: "Application Whitelisting Bypass via Bginfo"
aliases:
  - "/rule/aaf46cdc-934e-4284-b329-34aa701e3771"


tags:
  - attack.execution
  - attack.t1059.005
  - attack.defense_evasion
  - attack.t1218
  - attack.t1202



status: test





date: Sat, 26 Oct 2019 08:16:08 +0200


---

Execute VBscript code that is referenced within the *.bgi file.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml
* https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_bginfo.yml))
```yaml
title: Application Whitelisting Bypass via Bginfo
id: aaf46cdc-934e-4284-b329-34aa701e3771
status: test
description: Execute VBscript code that is referenced within the *.bgi file.
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Bginfo.yml
  - https://oddvar.moe/2017/05/18/bypassing-application-whitelisting-with-bginfo/
date: 2019/10/26
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\bginfo.exe'
    CommandLine|contains|all:
      - '/popup'
      - '/nolicprompt'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.execution
  - attack.t1059.005
  - attack.defense_evasion
  - attack.t1218
  - attack.t1202

```
