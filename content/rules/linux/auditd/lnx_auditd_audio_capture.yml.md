---
title: "Audio Capture"
aliases:
  - "/rule/a7af2487-9c2f-42e4-9bb9-ff961f0561d5"


tags:
  - attack.collection
  - attack.t1123



status: experimental





date: Sat, 4 Sep 2021 22:10:34 +0200


---

Detects attempts to record audio with arecord utility

<!--more-->


## Known false-positives

* None



## References

* https://linux.die.net/man/1/arecord
* https://linuxconfig.org/how-to-test-microphone-with-audio-linux-sound-architecture-alsa
* https://attack.mitre.org/techniques/T1123/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_audio_capture.yml))
```yaml
title: Audio Capture
id: a7af2487-9c2f-42e4-9bb9-ff961f0561d5
description: Detects attempts to record audio with arecord utility
    #the actual binary that arecord is using and that has to be monitored is /usr/bin/aplay 
author: 'Pawel Mazur'
status: experimental
date: 2021/09/04
references:
   - https://linux.die.net/man/1/arecord
   - https://linuxconfig.org/how-to-test-microphone-with-audio-linux-sound-architecture-alsa
   - https://attack.mitre.org/techniques/T1123/
logsource:
   product: linux
   service: auditd
detection:
   selection:
       type: EXECVE
       a0:
           - arecord
       a1:
           - '-vv'
       a2:
           - '-fdat'
   condition: selection
tags:
   - attack.collection
   - attack.t1123
falsepositives:
   - None
level: low

```
