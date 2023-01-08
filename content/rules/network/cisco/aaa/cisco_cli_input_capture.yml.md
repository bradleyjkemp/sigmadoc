---
title: "Cisco Show Commands Input"
aliases:
  - "/rule/b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b"
ruleid: b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b

tags:
  - attack.credential_access
  - attack.t1552.003



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

See what commands are being input into the device by other people, full credentials can be in the history

<!--more-->


## Known false-positives

* Not commonly run by administrators, especially if remote logging is configured




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_input_capture.yml))
```yaml
title: Cisco Show Commands Input
id: b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b
status: test
description: See what commands are being input into the device by other people, full credentials can be in the history
author: Austin Clark
date: 2019/08/11
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'show history'
    - 'show history all'
    - 'show logging'
  condition: keywords
fields:
  - CmdSet
falsepositives:
  - Not commonly run by administrators, especially if remote logging is configured
level: medium
tags:
  - attack.credential_access
  - attack.t1552.003

```
