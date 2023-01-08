---
title: "Account Enumeration on AWS"
aliases:
  - "/rule/e9c14b23-47e2-4a8b-8a63-d36618e33d70"
ruleid: e9c14b23-47e2-4a8b-8a63-d36618e33d70

tags:
  - attack.discovery
  - attack.t1592



status: experimental





date: Sun, 22 Nov 2020 00:33:47 +0800


---

Detects enumeration of accounts configuration via api call to list different instances and services within a short period of time.

<!--more-->


## Known false-positives

* AWS Config or other configuration scanning activities




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_enum_listing.yml))
```yaml
title: Account Enumeration on AWS
id: e9c14b23-47e2-4a8b-8a63-d36618e33d70 
status: experimental
description: Detects enumeration of accounts configuration via api call to list different instances and services within a short period of time.  
author: toffeebr33k
date: 2020/11/21
modified: 2021/08/09
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_eventname:
        eventName: list*
    timeframe: 10m
    condition: selection_eventname | count() > 50
fields:
    - userIdentity.arn
falsepositives:
    - AWS Config or other configuration scanning activities
level: low
tags:
    - attack.discovery
    - attack.t1592

```
