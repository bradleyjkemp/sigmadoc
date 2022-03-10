---
title: "Suspicious PowerShell Cmdline"
aliases:
  - "/rule/b6b49cd1-34d6-4ead-b1bf-176e9edba9a4"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the PowerShell command lines with reversed strings

<!--more-->


## Known false-positives

* Unlikely



## References

* https://2019.offzone.moscow/ru/report/hunting-for-powershell-abuses/
* https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=66


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_cmdline_reversed_strings.yml))
```yaml
title: Suspicious PowerShell Cmdline
id: b6b49cd1-34d6-4ead-b1bf-176e9edba9a4
status: test
description: Detects the PowerShell command lines with reversed strings
author: Teymur Kheirkhabarov (idea), Vasiliy Burov (rule), oscd.community, Tim Shelton
references:
  - https://2019.offzone.moscow/ru/report/hunting-for-powershell-abuses/
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=66
date: 2020/10/11
modified: 2022/02/21
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - 'hctac'
      - 'kearb'
      - 'dnammoc'
      - 'ekovn'
      - 'eliFd'
      - 'rahc'
      - 'etirw'
      - 'golon'
      - 'tninon'
      - 'eddih'
      - 'tpircS'
      - 'ssecorp'
      - 'llehsrewop'
      - 'esnopser'
      - 'daolnwod'
      - 'tneilCbeW'
      - 'tneilc'
      - 'ptth'
      - 'elifotevas'
      - '46esab'
      - 'htaPpmeTteG'
      - 'tcejbO'
      - 'maerts'
      - 'hcaerof'
      - 'ekovni'
      - 'retupmoc'
  filter_1:
    CommandLine|contains: '-EncodedCommand'
  condition: selection and not 1 of filter*
falsepositives:
  - Unlikely
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001

```
