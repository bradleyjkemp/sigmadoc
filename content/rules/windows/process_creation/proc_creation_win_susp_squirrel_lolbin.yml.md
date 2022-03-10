---
title: "Squirrel Lolbin"
aliases:
  - "/rule/fa4b21c9-0057-4493-b289-2556416ae4d7"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Wed, 3 Apr 2019 16:25:18 +0200


---

Detects Possible Squirrel Packages Manager as Lolbin

<!--more-->


## Known false-positives

* 1Clipboard
* Beaker Browser
* Caret
* Collectie
* Discord
* Figma
* Flow
* Ghost
* GitHub Desktop
* GitKraken
* Hyper
* Insomnia
* JIBO
* Kap
* Kitematic
* Now Desktop
* Postman
* PostmanCanary
* Rambox
* Simplenote
* Skype
* Slack
* SourceTree
* Stride
* Svgsus
* WebTorrent
* WhatsApp
* WordPress.com
* atom
* gitkraken
* slack
* teams



## References

* http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
* http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_squirrel_lolbin.yml))
```yaml
title: Squirrel Lolbin
id: fa4b21c9-0057-4493-b289-2556416ae4d7
status: experimental
description: Detects Possible Squirrel Packages Manager as Lolbin
references:
    - http://www.hexacorn.com/blog/2019/03/30/sqirrel-packages-manager-as-a-lolbin-a-k-a-many-electron-apps-are-lolbins-by-default/
    - http://www.hexacorn.com/blog/2018/08/16/squirrel-as-a-lolbin/
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218
author: Karneades / Markus Neis, Jonhnathan Ribeiro, oscd.community
date: 2019/11/12
modified: 2022/01/12
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\update.exe' # Check if folder Name matches executed binary  \\(?P<first>[^\\]*)\\Update.*Start.{2}(?P<second>\1)\.exe (example: https://regex101.com/r/SGSQGz/2)
        CommandLine|contains:
            - '--processStart'
            - '--processStartAndWait'
            - '--createShortcut'
        CommandLine|contains|all:
            - '.exe'
    filter1:
        CommandLine|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Discord\Update.exe'
            - ' --processStart Discord.exe'
    condition: selection and not 1 of filter*
falsepositives:
    - 1Clipboard
    - Beaker Browser
    - Caret
    - Collectie
    - Discord
    - Figma
    - Flow
    - Ghost
    - GitHub Desktop
    - GitKraken
    - Hyper
    - Insomnia
    - JIBO
    - Kap
    - Kitematic
    - Now Desktop
    - Postman
    - PostmanCanary
    - Rambox
    - Simplenote
    - Skype
    - Slack
    - SourceTree
    - Stride
    - Svgsus
    - WebTorrent
    - WhatsApp
    - WordPress.com
    - atom
    - gitkraken
    - slack
    - teams
level: medium
```