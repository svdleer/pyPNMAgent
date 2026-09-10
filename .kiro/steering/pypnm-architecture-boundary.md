# PyPNM Architecture Boundary

This architecture rule is mandatory and may not be bypassed.

## Required communication path

- The GUI communicates with the PyPNM API for all PyPNM operations.
- The PyPNM API is the sole boundary between the GUI and agents.
- Agents communicate bidirectionally only with the PyPNM API.
- All agent selection, task dispatch, SNMP/device access, file retrieval, parsing, plotting, and operational state belong behind the PyPNM API boundary.

## Prohibited paths

- Never add direct GUI-to-agent or agent-to-GUI communication.
- Never let the GUI dispatch agent tasks, connect to agent endpoints, or use agent credentials.
- Never bypass the API through shared files, databases, queues, sockets, proxy routes, or other indirect mechanisms.
- Never move API-owned device, agent, or capture-file operations into the GUI.
- Do not copy or expand an existing boundary violation. Identify it and ask the user before changing it.

If a requested change appears to require crossing this boundary, stop and ask the user. Do not implement a workaround or exception without explicit user direction.