# Kerberos TGT Monitor

Async Beacon Object File (BOF) that monitors for Kerberos logon events and wakes up the agent whenever a new Kerberos TGT is captured. Similar to Rubeus' `monitor` command, this BOF is running indefinitely and periodically checks the LSA ticket cache on the system. When a new TGT is detected, it prints the ticket metadata and outputs a base64-encoded kirbi blob that can be used for lateral movement via pass-the-ticket attacks.

>[!Important]
> This BOF requires asynchronous object file loading capabilities as it relies on the `BeaconWakeup` API to force an agent to check in when a new TGT is captured. Such functionality is provided by the [Conquest](https://github.com/jakobfriedl/conquest/) framework. 

## Workflow

In Conquest, the `tgt-monitor` BOF is executed in the background via a self-contained COFF loader DLL. The execution involves the following key steps:  

![Workflow](./assets/workflow.png)

1. The TGT Monitor BOF requires `NT AUTHORITY\SYSTEM` privileges.
   1. First, it checks the current process token for SYSTEM access.
   2. If the process token is not SYSTEM, the BOF scans all threads in the current process for an impersonation token with SYSTEM privileges and duplicates it. This allows use from a low-integrity agent process that has stolen a SYSTEM token (e.g. via `SeImpersonatePrivilege`). The BOF terminates if this also does not yield SYSTEM level access.
2. LSA and Kerberos authentication package handles are retrieved.
3. All active logon sessions are enumerated. For each session, the Kerberos ticket cache is queried and filtered for TGTs. If a `--user` argument was provided, only sessions matching that username are considered.
4. The current ticket cache is diffed against the previous snapshot. New TGTs trigger metadata printing and base64-encoded kirbi output, followed by a `BeaconWakeup()` call to force the agent to check in and return the output.
5. Steps 3 and 4 are repeated in a loop with until the BOF is cancelled via the stop event. The user defined interval sets the delay between polls.

## Usage

The following arguments need to be passed to the object file: 

| Name | Type | Description | 
| --- | --- | --- |
| `interval` | `int` | Timeout between checks in seconds. | 
| `targetUsers` | `string` | Case-insensitive comma-separated list of target usernames. When this field is set, only TGTs for the specified users are retrieved. Otherwise, TGTs are collected for all users. Note that computer accounts need to end with `$`. |

For ease-of-use, this repository features a [Conquest Module](./dist/tgt-monitor.py) that implements the following command.  

```
Usage: tgt-monitor [--interval interval] [--user user]
Example: tgt-monitor --interval 5 --user DC01$

Optional arguments:
  --interval interval       INT        Polling interval in seconds (default: 60).
  --user user               STRING     Comma-separated list of target usernames (default: all users).
```

![TGT Monitor](./assets/image.png)


The encoded ticket can be used directly with `Rubeus.exe ptt /ticket:<base64>` or `impacket-ticketConverter` for further lateral movement, as shown in the screenshot below. In [Conquest](https://github.com/jakobfriedl/conquest/), it is possible to use the `ptt` command to directly inject the ticket into the current logon session to impersonate the target user. 

![Stealing tickets with TGT Monitor](./assets/image-2.png)

## Installation

```bash
git clone https://github.com/jakobfriedl/tgt-monitor-bof
cd tgt-monitor-bof
make
```

From there, use Conquest's Script Manager to load the dist/tgt-monitor.py module.

## Acknowledgements 

This implementation of this Beacon Object File is based on the following projects: 

- https://github.com/Ghostpack/Rubeus
- https://github.com/RalfHacker/Kerbeus-BOF
- https://github.com/wavvs/nanorobeus