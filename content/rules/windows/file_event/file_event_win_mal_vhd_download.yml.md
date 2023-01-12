---
title: "Suspicious VHD Image Download From Browser"
aliases:
  - "/rule/8468111a-ef07-4654-903b-b863a80bbc95"
ruleid: 8468111a-ef07-4654-903b-b863a80bbc95

tags:
  - attack.resource_development
  - attack.t1587.001



status: test





date: Mon, 25 Oct 2021 09:07:22 +0200


---

Malware can use mountable Virtual Hard Disk .vhd file to encapsulate payloads and evade security controls

<!--more-->


## Known false-positives

* Legitimate user creation



## References

* https://redcanary.com/blog/intelligence-insights-october-2021/
* https://www.kaspersky.com/blog/lazarus-vhd-ransomware/36559/
* https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_mal_vhd_download.yml))
```yaml
title: Suspicious VHD Image Download From Browser
id: 8468111a-ef07-4654-903b-b863a80bbc95
status: test
description: Malware can use mountable Virtual Hard Disk .vhd file to encapsulate payloads and evade security controls
references:
    - https://redcanary.com/blog/intelligence-insights-october-2021/
    - https://www.kaspersky.com/blog/lazarus-vhd-ransomware/36559/
    - https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/
author: frack113, Christopher Peacock '@securepeacock', SCYTHE '@scythe_io'
date: 2021/10/25
modified: 2021/10/29
tags:
    - attack.resource_development
    - attack.t1587.001 
logsource:
    category: file_event
    product: windows
    definition: in sysmon add "<TargetFilename condition="end with">.vhd</TargetFilename> <!--vhd files for ZLoader and lazarus malware vectors -->"   
detection:
    selection:
        Image|endswith:
            - chrome.exe 
            - firefox.exe
            - microsoftedge.exe
            - microsoftedgecp.exe
            - msedge.exe
            - iexplorer.exe
            - brave.exe
            - opera.exe
        TargetFilename|contains: '.vhd' #not endswith to get the alternate data stream log Too TargetFilename: C:\Users\Frack113\Downloads\windows.vhd:Zone.Identifier
    condition: selection
falsepositives:
    - Legitimate user creation
level: medium

```