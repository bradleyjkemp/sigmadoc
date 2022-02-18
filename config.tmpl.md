---
title: "{{.Parsed.Title}}"

{{with .Time}}
date: {{.}}
{{end}}
---

## Raw config {{with .GitHubEditLink}}([edit]({{.}})){{end}}
```yaml
{{.Original}}
```
