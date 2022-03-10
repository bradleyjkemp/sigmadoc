---
title: "New Lolbin Process by Office Applications"
aliases:
  - "/rule/23daeb52-e6eb-493c-8607-c4f0246cb7d8"


tags:
  - attack.t1204.002
  - attack.t1047
  - attack.t1218.010
  - attack.execution
  - attack.defense_evasion



status: experimental





date: Mon, 30 Aug 2021 21:47:36 -0600


---

This rule will monitor any office apps that spins up a new LOLBin process. This activity is pretty suspicious and should be investigated.

<!--more-->


## Known false-positives

* Unknown



## References

* https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
* https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbins_by_office_applications.yml))
```yaml
title: New Lolbin Process by Office Applications
id: 23daeb52-e6eb-493c-8607-c4f0246cb7d8
description: This rule will monitor any office apps that spins up a new LOLBin process. This activity is pretty suspicious and should be investigated. 
references:
    - https://thedfirreport.com/2021/03/29/sodinokibi-aka-revil-ransomware/
    - https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Threat%20Intelligence/The%20DFIR%20Report/20210329_Sodinokibi_(aka_REvil)_Ransomware.yaml
author: 'Vadim Khrykov (ThreatIntel), Cyb3rEng (Rule)'
tags:
    - attack.t1204.002
    - attack.t1047
    - attack.t1218.010
    - attack.execution
    - attack.defense_evasion
status: experimental
date: 2021/08/23
logsource:
  product: windows
  category: process_creation
detection:
  #useful_information: add more LOLBins to the rules logic of your choice.
  selection1:
    Image|endswith:
      - 'regsvr32'
      - 'rundll32'
      - 'msiexec'
      - 'mshta'
      - 'verclsid'
  selection2:
    ParentImage|endswith:
      - winword.exe
      - excel.exe
      - powerpnt.exe
  condition: selection1 and selection2
falsepositives:
  - Unknown
level: high

```