---
title: "Suspicious Curl File Upload"
aliases:
  - "/rule/00bca14a-df4e-4649-9054-3f2aa676bc04"


tags:
  - attack.exfiltration
  - attack.t1567
  - attack.t1105



status: test





date: Fri, 3 Jul 2020 18:20:44 +0200


---

Detects a suspicious curl process start the adds a file to a web request

<!--more-->


## Known false-positives

* Scripts created by developers and admins



## References

* https://twitter.com/d1r4c/status/1279042657508081664
* https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md#atomic-test-19---curl-upload-file
* https://curl.se/docs/manpage.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_curl_fileupload.yml))
```yaml
title: Suspicious Curl File Upload
id: 00bca14a-df4e-4649-9054-3f2aa676bc04
status: test
description: Detects a suspicious curl process start the adds a file to a web request
author: Florian Roth
references:
  - https://twitter.com/d1r4c/status/1279042657508081664
  - https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md#atomic-test-19---curl-upload-file
  - https://curl.se/docs/manpage.html
date: 2020/07/03
modified: 2022/01/22
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\curl.exe'
    CommandLine|contains:
        - ' -F '
        - ' -T '
        - ' --upload-file '
        - ' -d '
        - ' --data '
  condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Scripts created by developers and admins
level: medium
tags:
  - attack.exfiltration
  - attack.t1567
  - attack.t1105

```