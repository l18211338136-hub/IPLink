const App = () => window.go?.main?.App;

let currentConfig = null;
let activeTunnels = [];
let editingIndex = -1;
let connectionState = "disconnected";
let localForwards = [];
let forwardStatuses = [];
let editingForwardIndex = -1;

const el = (id) => document.getElementById(id);

function showToast(msg, isError = false) {
  const t = el("toast");
  t.textContent = msg;
  t.className = isError ? "toast error" : "toast";
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.add("hidden"), 3200);
}

function fillForm(cfg) {
  currentConfig = cfg;
  el("serverAddr").value = cfg.server?.address || "";
  el("serverPort").value = cfg.server?.port || 29000;
  el("relayPort").value = cfg.server?.relay_port || 29001;
  el("natPort").value = cfg.server?.nat_port || 29002;
  el("clientId").value = cfg.client?.id || "windows-client-001";
  el("token").value = cfg.security?.token || "";
  el("allowedTargets").value = (cfg.security?.allowed_targets || []).join(", ");
  el("tlsEnabled").checked = Boolean(cfg.security?.tls_enabled);
  el("tlsSkipVerify").checked = Boolean(cfg.security?.tls_insecure_skip_verify);
  el("enableP2P").checked = cfg.network?.enable_p2p !== false;
  el("reconnectEnabled").checked = cfg.reconnect?.enabled !== false;
  renderTunnels();
}

function readForm() {
  const targets = el("allowedTargets")
    .value.split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    client: {
      id: el("clientId").value.trim(),
    },
    server: {
      address: el("serverAddr").value.trim(),
      port: Number(el("serverPort").value) || 29000,
      relay_port: Number(el("relayPort").value) || 29001,
      nat_port: Number(el("natPort").value) || 29002,
    },
    security: {
      tls_enabled: el("tlsEnabled").checked,
      tls_insecure_skip_verify: el("tlsSkipVerify").checked,
      token: el("token").value,
      allowed_targets: targets,
    },
    network: {
      enable_tcp: true,
      enable_udp: true,
      enable_p2p: el("enableP2P").checked,
    },
    reconnect: {
      enabled: el("reconnectEnabled").checked,
      max_attempts: currentConfig?.reconnect?.max_attempts || 0,
      interval_seconds: currentConfig?.reconnect?.interval_seconds || 5,
    },
    tunnels: currentConfig?.tunnels || [],
    logging: currentConfig?.logging || { level: "info", format: "text" },
  };
}

function renderTunnels() {
  const tunnels = currentConfig?.tunnels || [];
  el("tunnelCount").textContent = tunnels.length;
  const tbody = el("tunnelBody");
  if (tunnels.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">暂无隧道，点击右上角「+ 添加隧道」</td></tr>';
    return;
  }

  tbody.innerHTML = tunnels
    .map((t, idx) => {
      const target = t.protocol === "http" ? `${t.http_path || "/"}` : t.remote_addr || "-";
      const active = activeTunnels.find((a) => a.name === t.name);
      const statusHtml = active
        ? `<span class="bound-ok">${escapeHtml(active.bound_addr)}</span>`
        : `<span style="color:var(--muted)">未注册</span>`;
      return `
        <tr>
          <td>${escapeHtml(t.name)}</td>
          <td><span class="tag">${escapeHtml(t.protocol)}</span></td>
          <td>${escapeHtml(t.local_addr)}</td>
          <td>${escapeHtml(target)}</td>
          <td>${statusHtml}</td>
          <td>
            <button class="btn btn-ghost btn-sm" onclick="openEditModal(${idx})">编辑</button>
            <button class="btn btn-ghost btn-sm" style="color:#f87171" onclick="deleteTunnel(${idx})">删除</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function updateStatusUI(info) {
  connectionState = info.state || "disconnected";
  activeTunnels = info.active_tunnels || [];

  const badge = el("statusBadge");
  const text = el("statusText");
  const btn = el("btnConnect");

  badge.className = `badge badge-${connectionState}`;
  const labels = {
    disconnected: "未连接",
    connecting: "连接中...",
    connected: "已连接",
    reconnecting: "重连中...",
  };
  text.textContent = labels[connectionState] || connectionState;

  if (connectionState === "disconnected") {
    btn.textContent = "连接";
    btn.className = "btn btn-primary";
  } else {
    btn.textContent = "断开";
    btn.className = "btn btn-danger";
  }

  if (info.error) {
    showToast(info.error, true);
  }
  renderTunnels();
}

function appendLogLine(line) {
  const box = el("logContainer");
  const div = document.createElement("div");
  div.className = "log-line";
  if (line.includes("level=ERROR")) div.classList.add("log-error");
  else if (line.includes("level=WARN")) div.classList.add("log-warn");
  div.textContent = line;
  box.appendChild(div);

  while (box.children.length > 500) {
    box.removeChild(box.firstChild);
  }
  if (el("autoScroll").checked) {
    box.scrollTop = box.scrollHeight;
  }
}

function syncModalProto() {
  const proto = el("tProto").value;
  el("remoteGroup").classList.toggle("hidden", proto === "http");
  el("httpGroup").classList.toggle("hidden", proto !== "http");
}

window.openEditModal = function (idx) {
  editingIndex = idx;
  const t = currentConfig.tunnels[idx];
  el("modalTitle").textContent = "编辑隧道";
  el("tName").value = t.name || "";
  el("tProto").value = t.protocol || "tcp";
  el("tLocal").value = t.local_addr || "";
  el("tRemote").value = t.remote_addr || "";
  el("tHttpPath").value = t.http_path || "/";
  el("tStripPrefix").checked = t.strip_prefix !== false;
  syncModalProto();
  el("tunnelModal").classList.remove("hidden");
};

window.deleteTunnel = async function (idx) {
  currentConfig.tunnels.splice(idx, 1);
  renderTunnels();
  await App()?.SaveConfig(readForm());
};

function openAddModal() {
  editingIndex = -1;
  el("modalTitle").textContent = "添加隧道";
  el("tName").value = "";
  el("tProto").value = "tcp";
  el("tLocal").value = "127.0.0.1:";
  el("tRemote").value = "0.0.0.0:";
  el("tHttpPath").value = "/app";
  el("tStripPrefix").checked = true;
  syncModalProto();
  el("tunnelModal").classList.remove("hidden");
}

function closeModal() {
  el("tunnelModal").classList.add("hidden");
}

async function init() {
  if (!App()) {
    showToast("Wails 运行时未就绪", true);
    return;
  }

  const cfg = await App().GetConfig();
  fillForm(cfg);

  const status = await App().GetStatus();
  updateStatusUI(status);

  const logs = await App().GetLogs();
  (logs || []).forEach(appendLogLine);

  localForwards = (await App().GetLocalForwards()) || [];
  forwardStatuses = (await App().GetLocalForwardStatuses()) || [];
  renderForwards();
  setInterval(refreshForwardStatuses, 2000);

  window.runtime?.EventsOn("iplink:log", appendLogLine);
  window.runtime?.EventsOn("iplink:status", updateStatusUI);

  el("btnToggleToken").addEventListener("click", () => {
    const inp = el("token");
    const hidden = inp.type === "password";
    inp.type = hidden ? "text" : "password";
    el("btnToggleToken").textContent = hidden ? "隐藏" : "显示";
  });

  el("btnSave").addEventListener("click", async () => {
    try {
      const next = readForm();
      await App().SaveConfig(next);
      currentConfig = next;
      showToast("配置已保存");
    } catch (e) {
      showToast("保存失败: " + e, true);
    }
  });

  el("btnConnect").addEventListener("click", async () => {
    try {
      if (connectionState === "disconnected") {
        const next = readForm();
        currentConfig = next;
        await App().Connect(next);
      } else {
        await App().Disconnect();
      }
    } catch (e) {
      showToast("操作失败: " + e, true);
    }
  });

  el("btnImport").addEventListener("click", async () => {
    try {
      const imported = await App().ImportConfig();
      if (imported) {
        fillForm(imported);
        showToast("已导入配置");
      }
    } catch (e) {
      showToast("导入失败: " + e, true);
    }
  });

  el("btnExport").addEventListener("click", async () => {
    try {
      const path = await App().ExportConfig(readForm());
      if (path) showToast("已导出到: " + path);
    } catch (e) {
      showToast("导出失败: " + e, true);
    }
  });

  el("btnAddTunnel").addEventListener("click", openAddModal);
  el("btnCloseModal").addEventListener("click", closeModal);
  el("btnCancelModal").addEventListener("click", closeModal);
  el("tProto").addEventListener("change", syncModalProto);

  el("btnSaveTunnel").addEventListener("click", async () => {
    const proto = el("tProto").value;
    const item = {
      name: el("tName").value.trim() || `tunnel-${(currentConfig.tunnels?.length || 0) + 1}`,
      protocol: proto,
      local_addr: el("tLocal").value.trim(),
    };
    if (proto === "http") {
      item.http_path = el("tHttpPath").value.trim() || "/";
      item.strip_prefix = el("tStripPrefix").checked;
    } else {
      item.remote_addr = el("tRemote").value.trim();
    }

    if (!currentConfig.tunnels) currentConfig.tunnels = [];
    if (editingIndex >= 0) {
      currentConfig.tunnels[editingIndex] = item;
    } else {
      currentConfig.tunnels.push(item);
    }
    closeModal();
    renderTunnels();
    await App().SaveConfig(readForm());
  });

  el("btnClearLogs").addEventListener("click", async () => {
    el("logContainer").innerHTML = "";
    await App().ClearLogs();
  });

  el("btnAddForward").addEventListener("click", openAddForwardModal);
  el("btnCloseFModal").addEventListener("click", closeForwardModal);
  el("btnCancelFModal").addEventListener("click", closeForwardModal);
  el("btnSaveForward").addEventListener("click", saveForwardModal);
}

async function refreshForwardStatuses() {
  if (!App()) return;
  forwardStatuses = (await App().GetLocalForwardStatuses()) || [];
  renderForwards();
}

function renderForwards() {
  el("forwardCount").textContent = localForwards.length;
  const tbody = el("forwardBody");
  if (localForwards.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">暂无本地映射，例如 127.0.0.1:5000 → 127.0.0.1:6000</td></tr>';
    return;
  }
  tbody.innerHTML = localForwards
    .map((f, idx) => {
      const st = forwardStatuses[idx];
      let statusHtml = `<span style="color:var(--muted)">已停止</span>`;
      if (st?.running) {
        statusHtml = `<span class="bound-ok">运行中 (连接:${st.active_conns || 0})</span>`;
      } else if (st?.error) {
        statusHtml = `<span style="color:#f87171" title="${escapeHtml(st.error)}">失败</span>`;
      }
      return `
        <tr>
          <td>${escapeHtml(f.name)}</td>
          <td>${escapeHtml(f.listen_addr)}</td>
          <td>${escapeHtml(f.target_addr)}</td>
          <td>${statusHtml}</td>
          <td><input type="checkbox" ${f.enabled ? "checked" : ""} onchange="toggleForward(${idx}, this.checked)" /></td>
          <td>
            <button class="btn btn-ghost btn-sm" onclick="openEditForwardModal(${idx})">编辑</button>
            <button class="btn btn-ghost btn-sm" style="color:#f87171" onclick="deleteForward(${idx})">删除</button>
          </td>
        </tr>
      `;
    })
    .join("");
}

window.toggleForward = async function (idx, checked) {
  localForwards[idx].enabled = checked;
  forwardStatuses = (await App().SaveAndApplyLocalForwards(localForwards)) || [];
  renderForwards();
};

window.openEditForwardModal = function (idx) {
  editingForwardIndex = idx;
  const f = localForwards[idx];
  el("fModalTitle").textContent = "编辑本地端口映射";
  el("fName").value = f.name || "";
  el("fListen").value = f.listen_addr || "";
  el("fTarget").value = f.target_addr || "";
  el("fEnabled").checked = Boolean(f.enabled);
  el("forwardModal").classList.remove("hidden");
};

window.deleteForward = async function (idx) {
  localForwards.splice(idx, 1);
  forwardStatuses = (await App().SaveAndApplyLocalForwards(localForwards)) || [];
  renderForwards();
};

function openAddForwardModal() {
  editingForwardIndex = -1;
  el("fModalTitle").textContent = "添加本地端口映射";
  el("fName").value = "port-5000-to-6000";
  el("fListen").value = "127.0.0.1:5000";
  el("fTarget").value = "127.0.0.1:6000";
  el("fEnabled").checked = true;
  el("forwardModal").classList.remove("hidden");
}

function closeForwardModal() {
  el("forwardModal").classList.add("hidden");
}

async function saveForwardModal() {
  const item = {
    name: el("fName").value.trim() || `forward-${localForwards.length + 1}`,
    listen_addr: el("fListen").value.trim(),
    target_addr: el("fTarget").value.trim(),
    enabled: el("fEnabled").checked,
  };
  if (editingForwardIndex >= 0) {
    localForwards[editingForwardIndex] = item;
  } else {
    localForwards.push(item);
  }
  closeForwardModal();
  try {
    forwardStatuses = (await App().SaveAndApplyLocalForwards(localForwards)) || [];
    renderForwards();
    showToast("本地端口映射已更新");
  } catch (e) {
    showToast("应用映射失败: " + e, true);
  }
}

window.addEventListener("DOMContentLoaded", init);
