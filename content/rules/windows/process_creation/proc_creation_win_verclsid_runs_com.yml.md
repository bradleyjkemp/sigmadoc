---
title: "Verclsid.exe Runs COM Object"
aliases:
  - "/rule/d06be4b9-8045-428b-a567-740a26d9db25"
ruleid: d06be4b9-8045-428b-a567-740a26d9db25

tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects when verclsid.exe is used to run COM object via GUID

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Verclsid.yml
* https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5
* https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_verclsid_runs_com.yml))
```yaml
title: Verclsid.exe Runs COM Object
id: d06be4b9-8045-428b-a567-740a26d9db25
status: test
description: Detects when verclsid.exe is used to run COM object via GUID
author: Victor Sergeev, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Verclsid.yml
  - https://gist.github.com/NickTyrer/0598b60112eaafe6d07789f7964290d5
  - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
date: 2020/10/09
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  image_path:
    Image|endswith: '\verclsid.exe'
  cmd_s:
    CommandLine|contains: '/S'
  cmd_c:
    CommandLine|contains: '/C'
  condition: image_path and cmd_c and cmd_s
fields:
  - CommandLine
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
