---
title: "Possible Applocker Bypass"
aliases:
  - "/rule/82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719"
ruleid: 82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719

tags:
  - attack.defense_evasion
  - attack.t1218.004
  - attack.t1218.009
  - attack.t1127.001
  - attack.t1218.005
  - attack.t1218



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects execution of executables that can be used to bypass Applocker whitelisting

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment
* Using installutil to add features for .NET applications (primarily would occur in developer environments)



## References

* https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
* https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_possible_applocker_bypass.yml))
```yaml
title: Possible Applocker Bypass
id: 82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719
status: test
description: Detects execution of executables that can be used to bypass Applocker whitelisting
author: juju4
references:
  - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
  - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md
date: 2019/01/16
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - '\msdt.exe'
      - '\installutil.exe'
      - '\regsvcs.exe'
      - '\regasm.exe'
            # - '\regsvr32.exe'  # too many FPs, very noisy
      - '\msbuild.exe'
      - '\ieexec.exe'
            #- '\mshta.exe'
            #- '\csc.exe'
  condition: selection
falsepositives:
  - False positives depend on scripts and administrative tools used in the monitored environment
  - Using installutil to add features for .NET applications (primarily would occur in developer environments)
level: low
tags:
  - attack.defense_evasion
  - attack.t1218.004
  - attack.t1218.009
  - attack.t1127.001
  - attack.t1218.005
  - attack.t1218   # no way to map 1:1, so the technique level is required

```
