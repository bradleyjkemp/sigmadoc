---
title: "Suspicious PowerShell Parameter Substring"
aliases:
  - "/rule/36210e0d-5b19-485d-a087-c096088885f0"


tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious PowerShell invocation with a parameter substring

<!--more-->


## Known false-positives

* Penetration tests



## References

* http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_suspicious_parameter_variation.yml))
```yaml
title: Suspicious PowerShell Parameter Substring
id: 36210e0d-5b19-485d-a087-c096088885f0
status: test
description: Detects suspicious PowerShell invocation with a parameter substring
author: Florian Roth (rule), Daniel Bohannon (idea), Roberto Rodriguez (Fix)
references:
  - http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier
date: 2019/01/16
modified: 2022/02/23
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\Powershell.exe'
    CommandLine|contains:
      - ' -windowstyle h '
      - ' -windowstyl h'
      - ' -windowsty h'
      - ' -windowst h'
      - ' -windows h'
      - ' -windo h'
      - ' -wind h'
      - ' -win h'
      - ' -wi h'
      - ' -win h '
      - ' -win hi '
      - ' -win hid '
      - ' -win hidd '
      - ' -win hidde '
      - ' -NoPr '
      - ' -NoPro '
      - ' -NoProf '
      - ' -NoProfi '
      - ' -NoProfil '
      - ' -nonin '
      - ' -nonint '
      - ' -noninte '
      - ' -noninter '
      - ' -nonintera '
      - ' -noninterac '
      - ' -noninteract '
      - ' -noninteracti '
      - ' -noninteractiv '
      - ' -ec '
      - ' -encodedComman '
      - ' -encodedComma '
      - ' -encodedComm '
      - ' -encodedCom '
      - ' -encodedCo '
      - ' -encodedC '
      - ' -encoded '
      - ' -encode '
      - ' -encod '
      - ' -enco '
      - ' -en '
      - ' -executionpolic '
      - ' -executionpoli '
      - ' -executionpol '
      - ' -executionpo '
      - ' -executionp '
      - ' -execution bypass'
      - ' -executio bypass'
      - ' -executi bypass'
      - ' -execut bypass'
      - ' -execu bypass'
      - ' -exec bypass'
      - ' -exe bypass'
      - ' -ex bypass'
      - ' -ep bypass'
      - ' /windowstyle h '
      - ' /windowstyl h'
      - ' /windowsty h'
      - ' /windowst h'
      - ' /windows h'
      - ' /windo h'
      - ' /wind h'
      - ' /win h'
      - ' /wi h'
      - ' /win h '
      - ' /win hi '
      - ' /win hid '
      - ' /win hidd '
      - ' /win hidde '
      - ' /NoPr '
      - ' /NoPro '
      - ' /NoProf '
      - ' /NoProfi '
      - ' /NoProfil '
      - ' /nonin '
      - ' /nonint '
      - ' /noninte '
      - ' /noninter '
      - ' /nonintera '
      - ' /noninterac '
      - ' /noninteract '
      - ' /noninteracti '
      - ' /noninteractiv '
      - ' /ec '
      - ' /encodedComman '
      - ' /encodedComma '
      - ' /encodedComm '
      - ' /encodedCom '
      - ' /encodedCo '
      - ' /encodedC '
      - ' /encoded '
      - ' /encode '
      - ' /encod '
      - ' /enco '
      - ' /en '
      - ' /executionpolic '
      - ' /executionpoli '
      - ' /executionpol '
      - ' /executionpo '
      - ' /executionp '
      - ' /execution bypass'
      - ' /executio bypass'
      - ' /executi bypass'
      - ' /execut bypass'
      - ' /execu bypass'
      - ' /exec bypass'
      - ' /exe bypass'
      - ' /ex bypass'
      - ' /ep bypass'
  condition: selection
falsepositives:
  - Penetration tests
level: high
tags:
  - attack.execution
  - attack.t1059.001

```