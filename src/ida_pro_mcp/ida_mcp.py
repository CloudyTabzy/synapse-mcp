"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_kernwin
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


NETNODE_AUTOSTART = "$ ida_mcp.autostart"
NETNODE_CONFIG = "$ ida_mcp.config"
_ALT_PORT = 0
_ALT_PERSIST = 1
_SUP_HOST = 0


def _get_autostart() -> bool:
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)
    return val != 1


def _set_autostart(enabled: bool):
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def _get_port(default: int) -> int:
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PORT)
    return val if val != 0 else default


def _set_port(port: int):
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PORT, port)


def _get_host(default: str) -> str:
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.supstr(_SUP_HOST)
    return val if val else default


def _set_host(host: str):
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.supset(_SUP_HOST, host)


def _get_persist() -> bool:
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PERSIST)
    return val != 1


def _set_persist(enabled: bool):
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PERSIST, 2 if enabled else 1)


def _clear_endpoint():
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altdel(_ALT_PORT)
    node.supdel(_SUP_HOST)


def unload_package(package_name: str):
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    def __init__(self, host: str, port: int, autostart: bool, persist: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
<Autostart server when IDA opens:{autostart}>
<Save host and port to this database:{save_endpoint}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "checks": idaapi.Form.ChkGroupControl(
                    ("autostart", "save_endpoint"),
                    value=(1 if autostart else 0) | (2 if persist else 0),
                ),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port
        old_autostart = self.plugin.autostart
        old_persist = self.plugin.persist_endpoint

        form = MCPConfigForm(
            self.plugin.host,
            self.plugin.port,
            self.plugin.autostart,
            self.plugin.persist_endpoint,
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        autostart = bool(form.checks.value & 1)
        persist = bool(form.checks.value & 2)
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if persist != old_persist:
            self.plugin.persist_endpoint = persist
            _set_persist(persist)
            print(f"[MCP] Save host/port {'enabled' if persist else 'disabled'}")

        endpoint_changed = host != old_host or port != old_port
        self.plugin.host = host
        self.plugin.port = port

        if persist:
            _set_host(host)
            _set_port(port)
            if endpoint_changed or persist != old_persist:
                print(f"[MCP] Configuration updated: {host}:{port} (saved to IDB)")
        else:
            if persist != old_persist:
                _clear_endpoint()
            if endpoint_changed:
                print(f"[MCP] Configuration updated: {host}:{port} (not saved)")

        if not endpoint_changed and autostart == old_autostart and persist == old_persist:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        if endpoint_changed and self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        if self.plugin.autostart and ida_kernwin.is_idaq():
            print("[MCP] Autostarting server...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.autostart = _get_autostart()
        self.persist_endpoint = _get_persist()
        if self.persist_endpoint:
            self.host = _get_host(self.DEFAULT_HOST)
            self.port = _get_port(self.DEFAULT_PORT)
        else:
            self.host = self.DEFAULT_HOST
            self.port = self.DEFAULT_PORT

        if self.autostart and ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded, server will start automatically")
        elif not ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded (idalib mode, server managed externally)")
        else:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.discovery import unregister_instance
                else:
                    from ida_mcp.discovery import unregister_instance
                unregister_instance(port)
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    def run(self, arg):
        if self.mcp:
            self._unregister_instance()
            self.mcp.stop()
            self.mcp = None

        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, set_local_instance
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler, set_local_instance

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=IdaMcpHttpRequestHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                self.mcp = MCP_SERVER
                set_local_instance(self.host, port)
                self._register_instance(port)
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def _register_instance(self, port: int):
        try:
            if TYPE_CHECKING:
                from .ida_mcp.discovery import register_instance
            else:
                from ida_mcp.discovery import register_instance
            import os
            import idc
            import ida_nalt
            binary = ida_nalt.get_root_filename() or ""
            idb_path = idc.get_idb_path() or ""
            input_file = ida_nalt.get_input_file_path() or ""
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                idb_path=idb_path,
                input_file_path=input_file,
            )
            self._registered_port = port
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance registration failed: {e}")
            traceback.print_exc()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._unregister_instance()
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()
