fetch("/api/v1/openapi.json").then(r => r.json()).then(spec => {
  const container = document.getElementById("paths");
  container.textContent = "";
  const base = (spec.servers && spec.servers[0] && spec.servers[0].url) || "/api/v1";
  Object.entries(spec.paths || {}).forEach(([path, ops]) => {
    const shared = ops.parameters || [];
    ["get", "post", "put", "patch", "delete"].forEach(method => {
      const op = ops[method];
      if (!op) return;
      const wrap = document.createElement("div");
      wrap.className = "op";
      const title = document.createElement("h3");
      const badge = document.createElement("span");
      badge.className = "method " + method;
      badge.textContent = method.toUpperCase();
      title.appendChild(badge);
      title.appendChild(document.createTextNode(base + path));
      wrap.appendChild(title);
      if (op.summary) {
        const s = document.createElement("p");
        s.className = "desc";
        s.textContent = op.summary;
        wrap.appendChild(s);
      }
      if (op.description) {
        const d = document.createElement("p");
        d.className = "desc";
        d.textContent = op.description;
        wrap.appendChild(d);
      }
      const params = (op.parameters || []).concat(shared);
      if (params.length) {
        const p = document.createElement("p");
        p.className = "desc";
        p.textContent = "Parameters: " + params.map(function (param) {
          return (param.name || (param["$ref"] || "").split("/").pop());
        }).join(", ");
        wrap.appendChild(p);
      }
      container.appendChild(wrap);
    });
  });
}).catch(err => {
  document.getElementById("error").textContent = "Could not load the live API contract: " + err;
});
