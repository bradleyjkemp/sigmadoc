---
title: "AWS EC2 Download Userdata"
aliases:
  - "/rule/26ff4080-194e-47e7-9889-ef7602efed0c"
ruleid: 26ff4080-194e-47e7-9889-ef7602efed0c

tags:
  - attack.exfiltration
  - attack.t1020



status: experimental





date: Tue, 11 Feb 2020 23:25:54 +0200


---

Detects bulk downloading of User Data associated with AWS EC2 instances. Instance User Data may include installation scripts and hard-coded secrets for deployment.

<!--more-->


## Known false-positives

* Assets management software like device42



## References

* https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/ec2__download_userdata/main.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_ec2_download_userdata.yml))
```yaml
title: AWS EC2 Download Userdata
id: 26ff4080-194e-47e7-9889-ef7602efed0c
status: experimental
description: Detects bulk downloading of User Data associated with AWS EC2 instances. Instance User Data may include installation scripts and hard-coded secrets for deployment.
author: faloker
date: 2020/02/11
modified: 2021/08/20
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/ec2__download_userdata/main.py
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: ec2.amazonaws.com
        requestParameters.attribute: userData
        eventName: DescribeInstanceAttribute
    timeframe: 30m
    condition: selection_source | count() > 10
falsepositives:
    - Assets management software like device42
level: medium
tags:
    - attack.exfiltration 
    - attack.t1020

```
