---
title: "Download EXE from Suspicious TLD"
aliases:
  - "/rule/b5de2919-b74a-4805-91a7-5049accbaefe"


tags:
  - attack.initial_access
  - attack.t1566
  - attack.execution
  - attack.t1203
  - attack.t1204.002



status: test





date: Mon, 13 Mar 2017 16:11:43 +0100


---

Detects executable downloads from suspicious remote systems

<!--more-->


## Known false-positives

* All kind of software downloads




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_download_susp_tlds_whitelist.yml))
```yaml
title: Download EXE from Suspicious TLD
id: b5de2919-b74a-4805-91a7-5049accbaefe
status: test
description: Detects executable downloads from suspicious remote systems
author: Florian Roth
date: 2017/03/13
modified: 2021/11/27
logsource:
  category: proxy
detection:
  selection:
    c-uri-extension:
      - 'exe'
      - 'vbs'
      - 'bat'
      - 'rar'
      - 'ps1'
      - 'doc'
      - 'docm'
      - 'xls'
      - 'xlsm'
      - 'pptm'
      - 'rtf'
      - 'hta'
      - 'dll'
      - 'ws'
      - 'wsf'
      - 'sct'
      - 'zip'
            # If you want to add more extensions - see https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/
  filter:
    r-dns|endswith:
      - '.com'
      - '.org'
      - '.net'
      - '.edu'
      - '.gov'
      - '.uk'
      - '.ca'
      - '.de'
      - '.jp'
      - '.fr'
      - '.au'
      - '.us'
      - '.ch'
      - '.it'
      - '.nl'
      - '.se'
      - '.no'
      - '.es'
            # Extend this list as needed
  condition: selection and not filter
fields:
  - ClientIP
  - c-uri
falsepositives:
  - All kind of software downloads
level: low
tags:
  - attack.initial_access
  - attack.t1566
  - attack.execution
  - attack.t1203
  - attack.t1204.002

```
