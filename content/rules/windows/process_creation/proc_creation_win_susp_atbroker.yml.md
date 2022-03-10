---
title: "Suspicious Atbroker Execution"
aliases:
  - "/rule/f24bcaea-0cd1-11eb-adc1-0242ac120002"


tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Atbroker executing non-deafualt Assistive Technology applications

<!--more-->


## Known false-positives

* Legitimate, non-default assistive technology applications execution



## References

* http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
* https://lolbas-project.github.io/lolbas/Binaries/Atbroker/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_atbroker.yml))
```yaml
title: Suspicious Atbroker Execution
id: f24bcaea-0cd1-11eb-adc1-0242ac120002
description: Atbroker executing non-deafualt Assistive Technology applications
references:
    - http://www.hexacorn.com/blog/2016/07/22/beyond-good-ol-run-key-part-42/
    - https://lolbas-project.github.io/lolbas/Binaries/Atbroker/
status: experimental
author: Mateusz Wydra, oscd.community
date: 2020/10/12
modified: 2021/08/14
tags:
    - attack.defense_evasion
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'AtBroker.exe'
        CommandLine|contains: 'start'
    filter:
        CommandLine|contains:
            - animations
            - audiodescription
            - caretbrowsing
            - caretwidth
            - colorfiltering
            - cursorscheme
            - filterkeys
            - focusborderheight
            - focusborderwidth
            - highcontrast
            - keyboardcues
            - keyboardpref
            - magnifierpane
            - messageduration
            - minimumhitradius
            - mousekeys
            - Narrator
            - osk
            - overlappedcontent
            - showsounds
            - soundsentry
            - stickykeys
            - togglekeys
            - windowarranging
            - windowtracking
            - windowtrackingtimeout
            - windowtrackingzorder
    condition: selection and not filter
falsepositives:
    - Legitimate, non-default assistive technology applications execution
level: high

```
