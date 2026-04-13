# References — ingest-google-workspace-login-ocsf

## Source formats and schemas

- **Admin SDK Reports API `activities.list`** — https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
- **Workspace login audit activity events** — https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login
- **Workspace login activity report guide** — https://developers.google.com/workspace/admin/reports/v1/guides/manage-audit-login

## Output format

- **OCSF 1.8 Identity & Access Management category** — https://schema.ocsf.io/
- **OCSF 1.8 Authentication (3002)** — https://schema.ocsf.io/1.8.0/classes/authentication
- **OCSF 1.8 Account Change (3001)** — https://schema.ocsf.io/1.8.0/classes/account_change
- **OCSF 1.8 Metadata object** — https://schema.ocsf.io/1.8.0/objects/metadata
- **OCSF 1.8 Actor object** — https://schema.ocsf.io/1.8.0/objects/actor

## Collection guidance

The skill itself reads JSON from stdin or local files and does not call Google
Workspace APIs. Upstream collectors should:

- preserve raw `id.time`, `id.uniqueQualifier`, `id.applicationName`, actor IDs, and event parameters
- keep `events[]` intact because one activity can contain multiple event records
- page through `activities.list` outside this skill for large audit ranges

This first slice intentionally supports only the narrow verified login audit
event family documented above. New event names should be added only after
checking real Admin SDK payloads and the official Workspace audit appendix.
