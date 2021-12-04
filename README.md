# sg-exposure-check

Find AWS security groups that expose sensitive ports to the internet, and show which instances, load balancers and databases they actually reach.

## Planned scope

Collect security groups and network interfaces (describe_security_groups, describe_network_interfaces; moto + fixtures; offline JSON path), flag ingress from 0.0.0.0/0 or ::/0, all-ports/all-protocols rules, sensitive ports (SSH, RDP, DB ports, etc., configurable), resolve which ENIs (and their description/attachment: instance, ELB, RDS, Lambda) use each group so a finding says what is actually exposed; groups attached to nothing are lower severity. Strictly read-only.
