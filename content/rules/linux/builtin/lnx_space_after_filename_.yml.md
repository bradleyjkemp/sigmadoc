---
title: "Space After Filename"
aliases:
  - "/rule/879c3015-c88b-4782-93d7-07adf92dbcb7"
ruleid: 879c3015-c88b-4782-93d7-07adf92dbcb7

tags:
  - attack.execution



status: test





date: Mon, 13 Jul 2020 01:33:39 +0300


---

Detects space after filename

<!--more-->


## Known false-positives

* Typos



## References

* https://attack.mitre.org/techniques/T1064


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_space_after_filename_.yml))
```yaml
title: Space After Filename
id: 879c3015-c88b-4782-93d7-07adf92dbcb7
status: test
description: Detects space after filename
author: Ömer Günal
references:
  - https://attack.mitre.org/techniques/T1064
date: 2020/06/17
modified: 2021/11/27
logsource:
  product: linux
detection:
  selection1:
    - 'echo "*" > * && chmod +x *'
  selection2:
    - 'mv * "* "'
  condition: selection1 and selection2
falsepositives:
  - Typos
level: low
tags:
  - attack.execution

```
