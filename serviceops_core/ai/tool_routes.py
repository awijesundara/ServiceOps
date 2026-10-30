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
        """Connect or edit a server. Only the name and MCP address are always needed: how to sign in is found from
        the server itself (MCP authorization: RFC 9728 resource metadata, RFC 8414/OIDC discovery), and the form
        then asks only for what cannot be discovered: an OAuth client ID and secret, or an access token."""
        service.actor(current_user)
        form = request.form
        server_id = form.get("server_id", "").strip()
        server = owned_server(server_id) if server_id else None
        name = " ".join(form.get("name", "").split())[:80]
        role = form.get("minimum_role", server.minimum_role if server else "agent")
        secret = form.get("auth_value", "").strip()
        custom_header = form.get("auth_header", "").strip()
        manual_token_url = form.get("token_url", "").strip()
        token_scope = " ".join(form.get("token_scope", "").split())[:300]
        client_id = form.get("client_id", "").strip()
        try:
            if not name:
                raise mcp.McpError(tr("Enter a name for the server."))
            if role not in mcp.TOOL_ROLES:
                raise mcp.McpError(tr("Choose one of the listed roles."))
            if custom_header and not mcp._HEADER_NAME.fullmatch(custom_header):
                raise mcp.McpError(tr("The credential header name may contain only letters, digits and hyphens."))
            if len(secret) > 4000:
                raise mcp.McpError(tr("The credential is too long."))
            if client_id and (len(client_id) > 200 or not all(33 <= ord(ch) <= 126 for ch in client_id)):
                raise mcp.McpError(tr("Enter a valid OAuth client ID."))
            if any(not 33 <= ord(ch) <= 126 for ch in token_scope.replace(" ", "")):
                raise mcp.McpError(tr("The scope may contain only visible characters and spaces."))
            url = mcp.check_destination(form.get("url", ""))[0]
            clash = AIToolServer.query.filter(AIToolServer.tenant_id == current_user.tenant_id, AIToolServer.name == name,
                                              AIToolServer.id != (server.id if server else "")).first()
            if clash:
                raise mcp.McpError(tr("Another server already uses this name."))
            if custom_header:  # advanced: a fixed header the server documents, no discovery
                found = {"method": "header"}
            else:
                found = mcp.probe(url)
                if found["method"] == "oauth" and manual_token_url:
                    found["token_url"] = mcp.check_destination(manual_token_url)[0]
        except mcp.McpError as error:
            flash(str(error), "error")
            return back()
        method = found["method"]
        creating = server is None
        if creating:
            server = AIToolServer(tenant_id=current_user.tenant_id, url=url)
            db.session.add(server)
        previous = None if creating else (server.url, server.auth_mode if server.auth_mode != "client_credentials" else "oauth",
                                          server.auth_header, server.issuer, server.client_id)
        current = (url, method, custom_header or mcp.DEFAULT_AUTH_HEADER, found.get("issuer", ""),
                   client_id if method == "oauth" else "")
        moved = previous is not None and previous != current
        if moved:
            # A credential belongs to one destination and sign-in method; another server may offer other tools.
            server.auth_encrypted = ""
            for tool in server.tools:
                tool.enabled = False
        server.name, server.url, server.minimum_role, server.auth_mode = name, url, role, method
        server.auth_header = custom_header or mcp.DEFAULT_AUTH_HEADER
        server.issuer, server.resource = found.get("issuer", ""), found.get("resource", "")
        server.token_url, server.token_url_manual = found.get("token_url", ""), bool(manual_token_url and method == "oauth")
        server.client_id = client_id if method == "oauth" else ""
        server.token_scope = token_scope if method == "oauth" else ""
        server.share_external = form.get("share_external") == "on"
        server.enabled = form.get("enabled", "on") == "on"
        if method == "none":
            server.auth_encrypted = ""
        elif secret:
            server.auth_encrypted = mcp.encrypt_credential(secret[7:].strip() if method == "bearer" and secret.lower().startswith("bearer ") else secret)
        elif form.get("clear_auth") == "on":
            server.auth_encrypted = ""
        db.session.flush()
        mcp.forget_token(server.id)
        audit("ai tool server created" if creating else "ai tool server updated", f"Connected tools: {server.name}",
              f"url={url}; sign_in={method}; issuer={server.issuer or '-'}; client={server.client_id or '-'}; role={role}; "
              f"share_external={server.share_external}; enabled={server.enabled}; "
              f"credential={'set' if server.auth_encrypted else 'none'}" + ("; tools disabled after the sign-in changed" if moved else ""))
        db.session.commit()
        needs = {"oauth": not (server.client_id and server.auth_encrypted), "bearer": not server.auth_encrypted,
                 "header": not server.auth_encrypted}.get(method, False)
        if needs:
            flash(tr("{name} signs in through {issuer}. Enter the client ID and secret registered for ServiceOps there, "
                     "then save.", name=server.name, issuer=server.issuer) if method == "oauth" else
                  tr("{name} needs an access token or API key. Enter it, then save.", name=server.name), "success")
            return redirect(url_for("ai.settings") + f"#server-{server.id}")
        discover(server)
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
