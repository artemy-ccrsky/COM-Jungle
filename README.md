<p align="center">
  <img src="images/COMjungle_logo.png" alt="COM Jungle" width="420">
</p>

# COM Jungle

> Ancient Windows magic in modern attacks.

COM is one of the oldest pieces of Windows, and it is still everywhere.

For developers, it is a component and integration model. For attackers, it is an attack surface that can shape **execution, persistence, trust boundaries, lateral movement, and defense evasion**.

**COM is everywhere. Most people just stopped looking.**

For decades, Windows has built applications, services, automation, IPC, and system components on top of COM. The machinery is old, deeply integrated, and still flexible.

This repository walks the jungle behind `CoCreateInstance`:

- **What** gets activated?
- **Where** does it run?
- **Who** does it run as?
- **How** does the call cross a process, a session, or a machine?
- **What changes** when one link in the chain moves?

One link is enough to change the outcome:

**a different DLL.**
**a different process.**
**a different token.**
**a different session.**
**a different machine.**

## Map

Start at the top. The later notes assume the one above them.


| Note                                                      | Tactic                                                         |
| --------------------------------------------------------- | -------------------------------------------------------------- |
| ⚙️ [How COM works](fundamentals.md)                       | The base. Every tactic below is one link of the same chain.    |
| ⚡ [Execution](execution.md)                               | Execution. Get code running in a chosen process.               |
| 🚧 [Trust boundaries](trust-boundaries.md)                | Privilege escalation. Cross integrity, user, or session.       |
| 🌐 [Lateral movement](lateral-movement.md)                | Lateral movement. Activate the class on another machine.       |
| 📌 [Persistence](persistence.md)                          | Persistence. A normal program loads your class later.          |
| 📬 [Initial access](initial-access.md)                    | Initial access. Delivery waits, then COM runs it.              |
| 🔬 [Research](vulnerability-research.md)                  | Finding the next class. Not one finished tactic!               |
| 🛡️ [Detection and hardening](detection-and-hardening.md) | Defense. What to correlate, and what a control actually stops. |


## How to read

- New to COM: [fundamentals](fundamentals.md), then [execution](execution.md).
- Hunting a primitive: [fundamentals](fundamentals.md), then [research](vulnerability-research.md). The other notes are maps of surfaces.
- Writing a detection: activation and execution first, then [detection](detection-and-hardening.md). A single CLSID signature goes stale. The registration, the load, and the process context do not.

A CLSID from someone else's write-up is a lead. Registrations, ACLs, and DCOM hardening change between builds. Record the build, the bitness, the token, the session, and the effective key before treating a result as general.

> [!WARNING]
> Lab or study only.
>
> Use this on systems you own, or where you have explicit permission to test. It is not a procedure for systems you do not control.



Built by Artemy Tsetsersky in 2026

