---
title: "File Download with Headless Browser"
aliases:
  - "/rule/0e8cfe08-02c9-4815-a2f8-0d157b7ed33e"
ruleid: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e

tags:
  - attack.command_and_control
  - attack.t1105







date: Tue, 4 Jan 2022 13:47:23 +0800


---

This is an unusual method to download files. It starts a browser headless and downloads a file from a location. This can be used by threat actors to download files.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/mrd0x/status/1478234484881436672?s=12


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_headless_browser_file_download.yml))
```yaml
title: File Download with Headless Browser
id: 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e
description: This is an unusual method to download files. It starts a browser headless and downloads a file from a location. This can be used by threat actors to download files.
author: Sreeman, Florian Roth
date: 2022/01/04
references:
  - https://twitter.com/mrd0x/status/1478234484881436672?s=12
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\msedge.exe'
      - '\chrome.exe'
    CommandLine|contains|all:
      - '--headless'
      - 'dump-dom'
      - 'http'
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: high

```