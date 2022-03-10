---
title: "APT29"
aliases:
  - "/rule/033fe7d6-66d1-4240-ac6b-28908009c71f"


tags:
  - attack.execution
  - attack.g0016
  - attack.t1059.001



status: test





date: Sun, 13 Aug 2017 16:20:25 -0400


---

This method detects a suspicious PowerShell command line combination as used by APT29 in a campaign against U.S. think tanks.

<!--more-->


## Known false-positives

* unknown



## References

* https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/
* https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_apt29_thinktanks.yml))
```yaml
title: APT29
id: 033fe7d6-66d1-4240-ac6b-28908009c71f
status: test
description: This method detects a suspicious PowerShell command line combination as used by APT29 in a campaign against U.S. think tanks.
author: Florian Roth
references:
  - https://www.microsoft.com/security/blog/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/
  - https://www.fireeye.com/blog/threat-research/2018/11/not-so-cozy-an-uncomfortable-examination-of-a-suspected-apt29-phishing-campaign.html
date: 2018/12/04
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '-noni'
      - '-ep'
      - 'bypass'
      - '$'
  condition: selection
falsepositives:
  - unknown
level: critical
tags:
  - attack.execution
  - attack.g0016
  - attack.t1059.001

```
