---
title: "Installation of TeamViewer Desktop"
aliases:
  - "/rule/9711de76-5d4f-4c50-a94f-21e4e8f8384d"
ruleid: 9711de76-5d4f-4c50-a94f-21e4e8f8384d

tags:
  - attack.command_and_control
  - attack.t1219



status: experimental





date: Fri, 28 Jan 2022 16:12:38 +0100


---

TeamViewer_Desktop.exe is create during install

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-1---teamviewer-files-detected-test-on-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_install_teamviewer_desktop.yml))
```yaml
title: Installation of TeamViewer Desktop
id: 9711de76-5d4f-4c50-a94f-21e4e8f8384d
status: experimental
description: TeamViewer_Desktop.exe is create during install 
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1219/T1219.md#atomic-test-1---teamviewer-files-detected-test-on-windows
date: 2022/01/28
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: \TeamViewer_Desktop.exe
  condition: selection 
falsepositives:
  - Unknown
level: medium
tags:
  - attack.command_and_control
  - attack.t1219

```
