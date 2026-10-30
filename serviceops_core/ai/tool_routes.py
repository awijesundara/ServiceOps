"""Administration of connected tools (MCP servers) for the chat assistant."""
from flask import abort, flash, redirect, request, url_for
from flask_login import current_user

from serviceops_core.ai import mcp, service
from serviceops_core.localization import tr
from serviceops_models import AITool, AIToolServer, db


def servers_for(tenant_id):
    return AIToolServer.query.filter_by(tenant_id=tenant_id).order_by(AIToolServer.name).all()


def add_routes(blueprint):
    from app import audit, require_action, roles

    def owned_server(server_id):
        server = AIToolServer.query.filter_by(id=server_id, tenant_id=current_user.tenant_id).first()
        if not server:
            abort(404)
        return server

    def back():
        return redirect(url_for("ai.settings") + "#aiadm-tools")

    def discover(server):
        try:
            found, skipped = mcp.discover(server)
        except mcp.McpError as error:
            db.session.commit()  # keep the failed status on the server
            flash(tr("Could not read the tools of {name}: {reason}", name=server.name, reason=str(error)), "error")
            return False
        audit("ai tool server discovered", f"Connected tools: {server.name}",
              f"tools={found}; skipped={skipped}; enabled={sum(1 for t in server.tools if t.enabled)}")
        db.session.commit()
        message = tr("{name}: {count} tools found. Enable the ones the assistant may use.", name=server.name, count=found)
        if skipped:
            message += " " + tr("{count} could not be used (invalid name or input description).", count=skipped)
        flash(message, "success")
        return True

    @blueprint.route("/admin/ai/tools/servers", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def tool_server_save():
        service.actor(current_user)
        server_id = request.form.get("server_id", "").strip()
        server = owned_server(server_id) if server_id else None
        name = " ".join(request.form.get("name", "").split())[:80]
        header = request.form.get("auth_header", "").strip() or mcp.DEFAULT_AUTH_HEADER
        role = request.form.get("minimum_role", "agent")
        secret = request.form.get("auth_value", "").strip()
        mode = request.form.get("auth_mode", "header")
        token_url, client_id = "", ""
        token_scope = " ".join(request.form.get("token_scope", "").split())[:300]
        try:
            if mode not in mcp.AUTH_MODES:
                raise mcp.McpError(tr("Choose one of the listed sign-in methods."))
            if mode == "client_credentials":
                client_id = request.form.get("client_id", "").strip()
                if not client_id or len(client_id) > 200 or not all(33 <= ord(ch) <= 126 for ch in client_id):
                    raise mcp.McpError(tr("Enter the OAuth client ID."))
                if any(not 33 <= ord(ch) <= 126 for ch in token_scope.replace(" ", "")):
                    raise mcp.McpError(tr("The scope may contain only visible characters and spaces."))
                token_url = mcp.check_destination(request.form.get("token_url", ""))[0]
                if not secret and not (server and server.auth_mode == "client_credentials" and server.auth_encrypted):
                    raise mcp.McpError(tr("Enter the OAuth client secret."))
            if not name:
                raise mcp.McpError(tr("Enter a name for the server."))
            if role not in mcp.TOOL_ROLES:
                raise mcp.McpError(tr("Choose one of the listed roles."))
            if not mcp._HEADER_NAME.fullmatch(header):
                raise mcp.McpError(tr("The credential header name may contain only letters, digits and hyphens."))
            if len(secret) > 4000:
                raise mcp.McpError(tr("The credential is too long."))
            url = mcp.check_destination(request.form.get("url", ""))[0]
            clash = AIToolServer.query.filter(AIToolServer.tenant_id == current_user.tenant_id, AIToolServer.name == name,
                                              AIToolServer.id != (server.id if server else "")).first()
            if clash:
                raise mcp.McpError(tr("Another server already uses this name."))
        except mcp.McpError as error:
            flash(str(error), "error")
            return back()
        creating = server is None
        if creating:
            server = AIToolServer(tenant_id=current_user.tenant_id, url=url)
            db.session.add(server)
        moved = not creating and (server.url != url or server.auth_header != header or server.auth_mode != mode
                                  or server.token_url != token_url or server.client_id != client_id)
        if moved:
            # A credential belongs to one destination, and a different server may offer different tools.
            server.auth_encrypted = ""
            for tool in server.tools:
                tool.enabled = False
        server.name, server.url, server.auth_header, server.minimum_role = name, url, header, role
        server.auth_mode, server.token_url, server.client_id, server.token_scope = mode, token_url, client_id, token_scope
        server.share_external = request.form.get("share_external") == "on"
        server.enabled = request.form.get("enabled", "on") == "on"
        if secret:
            server.auth_encrypted = mcp.encrypt_credential(secret)
        elif request.form.get("clear_auth") == "on":
            server.auth_encrypted = ""
        db.session.flush()
        mcp.forget_token(server.id)
        audit("ai tool server created" if creating else "ai tool server updated", f"Connected tools: {server.name}",
              f"url={url}; sign_in={mode}; client={client_id or '-'}; role={role}; share_external={server.share_external}; enabled={server.enabled}; "
              f"credential={'set' if server.auth_encrypted else 'none'}" + ("; tools disabled after the address changed" if moved else ""))
        db.session.commit()
        if creating or moved:
            discover(server)
        else:
            flash(tr("Saved {name}.", name=server.name), "success")
        return back()

    @blueprint.route("/admin/ai/tools/servers/<server_id>/discover", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def tool_server_discover(server_id):
        service.actor(current_user)
        discover(owned_server(server_id))
        return back()

    @blueprint.route("/admin/ai/tools/servers/<server_id>/delete", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def tool_server_delete(server_id):
        service.actor(current_user)
        server = owned_server(server_id)
        name = server.name
        mcp.forget_token(server.id)
        db.session.delete(server)
        audit("ai tool server removed", f"Connected tools: {name}")
        db.session.commit()
        flash(tr("Removed {name} and its tools.", name=name), "success")
        return back()

    @blueprint.route("/admin/ai/tools/<tool_id>/enabled", methods=["POST"])
    @roles("admin")
    @require_action("administer")
    def tool_enabled(tool_id):
        service.actor(current_user)
        tool = AITool.query.filter_by(id=tool_id, tenant_id=current_user.tenant_id).first()
        if not tool:
            abort(404)
        enable = request.form.get("enabled") == "on"
        if enable:
            allowed, reason = mcp.may_enable(tool, request.form.get("confirm_read_only") == "on")
            if not allowed:
                flash(reason, "error")
                return back()
        tool.enabled = enable
        audit("ai tool enabled" if enable else "ai tool disabled", f"Connected tools: {tool.server.name} / {tool.name}",
              f"read_only_hint={tool.read_only}; confirmed={request.form.get('confirm_read_only') == 'on'}")
        db.session.commit()
        return back()
