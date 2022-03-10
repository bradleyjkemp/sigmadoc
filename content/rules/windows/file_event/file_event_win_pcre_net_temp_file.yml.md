---
title: "PCRE.NET Package Temp Files"
aliases:
  - "/rule/6e90ae7a-7cd3-473f-a035-4ebb72d961da"


tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects processes creating temp files related to PCRE.NET package

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/rbmaslen/status/1321859647091970051
* https://twitter.com/tifkin_/status/1321916444557365248


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_pcre_net_temp_file.yml))
```yaml
title: PCRE.NET Package Temp Files
id: 6e90ae7a-7cd3-473f-a035-4ebb72d961da
description: Detects processes creating temp files related to PCRE.NET package
status: experimental
date: 2020/10/29
modified: 2021/08/14
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.execution
    - attack.t1059
references:
    - https://twitter.com/rbmaslen/status/1321859647091970051
    - https://twitter.com/tifkin_/status/1321916444557365248
logsource:
    category: file_event
    product: windows
detection:
    selection: 
        TargetFilename|contains: \AppData\Local\Temp\ba9ea7344a4a5f591d6e5dc32a13494b\
    condition: selection
falsepositives:
    - Unknown
level: high

```
