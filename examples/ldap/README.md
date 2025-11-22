# LDAP Collector
## Artifacts
- [ldap-model.json](ldap-model.json): the custom icon schema for LDAP nodes
- [example-ldap-collection-definitions.json](example-ldap-collection-definitions.json): example collection definitions for OpenDJ Users and Groups

## LDAP Queries
The following LDAP queries are used to collect node and edge data
| Data Element (Type) | Search Base | Filter | Attributes Requested |
|---|---|---|---|
| Users (Nodes) | ou=People,dc=example | (objectClass=person) | cn, uid, sn, pwdChangedTime, entryUUID  |
| Groups (Nodes) | ou=Groups,dc=example | (objectClass=groupOfNames) | cn, member |
| Group Memberships (Edge) | ou=Groups,dc=example | (objectClass=groupOfNames) | cn, member |