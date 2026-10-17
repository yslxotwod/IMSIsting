# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## Current state in this repo

These five labels are **not created yet** on `yslxotwod/IMSIsting`. The only pre-existing
`wontfix` is GitHub's stock label with a different description (`This will not be worked on`),
which is semantically compatible — reuse it rather than creating a duplicate.

Create them on demand when `/triage` first needs them:

```bash
gh label create needs-triage    --description "Maintainer needs to evaluate" --color "ededed"
gh label create needs-info      --description "Waiting on reporter for more information" --color "ededed"
gh label create ready-for-agent --description "Fully specified, ready for an AFK agent" --color "0e8a16"
gh label create ready-for-human --description "Requires human implementation" --color "fbca04"
# wontfix already exists (GitHub default)
```

`/triage` additionally uses the two category roles `bug` and `enhancement`, both of which
already exist as GitHub defaults. Exactly one category role and one state role per triaged issue.
