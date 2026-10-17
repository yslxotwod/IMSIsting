# Wayfinder Labels

`/wayfinder` requires five owner-qualified labels. They are **required** — every wayfinder map
and ticket carries one, and they are never applied by any other skill.

| Label               | Applied to                                       |
| ------------------- | ------------------------------------------------ |
| `wayfinder:map`     | The single map issue that holds the effort       |
| `wayfinder:research`| A ticket resolved by reading outside knowledge   |
| `wayfinder:prototype`| A ticket resolved by a rough concrete artifact  |
| `wayfinder:grilling`| A ticket resolved by conversation (the default)  |
| `wayfinder:task`    | A ticket resolved by doing manual work first     |

Every child ticket carries exactly one `wayfinder:<type>` label. Maps never carry a type label;
tickets never carry `wayfinder:map`.

## Current state in this repo

These five labels are **not created yet** on `yslxotwod/IMSIsting`. Create them before charting
the first map:

```bash
gh label create "wayfinder:map"       --description "Wayfinder map (canonical artifact)"   --color "5319e7"
gh label create "wayfinder:research"  --description "Wayfinder ticket: research (AFK)"      --color "5319e7"
gh label create "wayfinder:prototype" --description "Wayfinder ticket: prototype (HITL)"    --color "5319e7"
gh label create "wayfinder:grilling"  --description "Wayfinder ticket: grilling (HITL)"     --color "5319e7"
gh label create "wayfinder:task"      --description "Wayfinder ticket: task (HITL or AFK)"  --color "5319e7"
```

Creating a label is not the same as applying one: only `/wayfinder` applies these, only with the
`wayfinder:` prefix, and only to the map/ticket it is actually charting.
