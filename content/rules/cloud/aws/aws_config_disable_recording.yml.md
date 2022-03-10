---
title: "AWS Config Disabling Channel/Recorder"
aliases:
  - "/rule/07330162-dba1-4746-8121-a9647d49d297"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Tue, 21 Jan 2020 15:07:10 +0200


---

Detects AWS Config Service disabling

<!--more-->


## Known false-positives

* Valid change in AWS Config Service




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_config_disable_recording.yml))
```yaml
title: AWS Config Disabling Channel/Recorder
id: 07330162-dba1-4746-8121-a9647d49d297
status: experimental
description: Detects AWS Config Service disabling
author: vitaliy0x1
date: 2020/01/21
modified: 2021/08/09
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: config.amazonaws.com
        eventName:
            - DeleteDeliveryChannel
            - StopConfigurationRecorder
    condition: selection_source
falsepositives:
    - Valid change in AWS Config Service
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001

```