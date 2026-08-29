import { FormEvent, useEffect, useMemo, useRef, useState } from "react";

type Page = "dashboard" | "servers" | "clients" | "audit" | "users";
type User = { id: string; username: string; isAdmin: boolean; isSuperAdmin: boolean; manualLocked: boolean; failedAttempts: number; lockedUntil?: string | null; createdAt: string };
type AuthStatus = { needsDatabaseSetup: boolean; needsSetup: boolean; siteName: string; user?: User };
type Server = { id: string; name: string; endpoint: string; status: string; configRevision: number; publicIps: string[]; platform: string; architecture: string; fullMapping: boolean };
type Client = { id: string; serverId: string; name: string; platform: string; status: string };
type Mapping = { id: string; serverId: string; clientId: string; protocol: "tcp" | "udp" | "both"; mappingType: "port" | "full"; publicIp: string; publicPort: number; targetHost: string; targetPort: number; excludedPorts?: string; accessMode: "public" | "allowlist"; allowedIps?: string; priority: number; status: string; occupiedByMappingId?: string };
type AuditLog = { id: number; action: string; resourceType: string; resourceId: string; detail: string; createdAt: string };
type DownloadTarget = { role: "server"; server: Server } | { role: "client"; client: Client };

const baseNav: Array<[Page, string]> = [["dashboard", "工作台"], ["servers", "服务端"], ["clients", "客户端"], ["audit", "审计日志"]];

export function App() {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [siteName, setSiteName] = useState("Matrix Tunnel Proxy");
  const [error, setError] = useState("");
  const loadStatus = async () => {
    try {
      const response = await fetch("/api/v1/auth/status");
      if (!response.ok) throw new Error("无法连接控制中心");
      const nextStatus = await response.json() as AuthStatus;
      setStatus(nextStatus);
      setSiteName(nextStatus.siteName || "Matrix Tunnel Proxy");
      setError("");
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "请求失败"); }
  };
  useEffect(() => { void loadStatus(); }, []);
  useEffect(() => { document.title = `${siteName} 控制中心`; }, [siteName]);
  if (!status) return <AuthScreen siteName={siteName} loading error={error} setup={false} onAuthenticated={() => void loadStatus()} />;
  if (status.needsDatabaseSetup) return <DatabaseSetupScreen siteName={siteName} onReady={() => void loadStatus()} />;
  if (status.needsSetup) return <AuthScreen siteName={siteName} error={error} setup onAuthenticated={() => void loadStatus()} />;
  if (!status.user) return <AuthScreen siteName={siteName} error={error} setup={false} onAuthenticated={(user) => setStatus({ needsDatabaseSetup: false, needsSetup: false, siteName, user })} />;
  return <ConsoleApp siteName={siteName} currentUser={status.user} onSignedOut={() => setStatus({ needsDatabaseSetup: false, needsSetup: false, siteName })} />;
}

function ConsoleApp({ siteName, currentUser, onSignedOut }: { siteName: string; currentUser: User; onSignedOut: () => void }) {
  const [page, setPage] = useState<Page>("dashboard");
  const [servers, setServers] = useState<Server[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [effectiveMappings, setEffectiveMappings] = useState(0);
  const [recentEvents, setRecentEvents] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showServerForm, setShowServerForm] = useState(false);
  const [showClientForm, setShowClientForm] = useState(false);
  const [downloadTarget, setDownloadTarget] = useState<DownloadTarget | null>(null);
  const [showPasswordForm, setShowPasswordForm] = useState(false);
  const [showAccountMenu, setShowAccountMenu] = useState(false);
  const accountAreaRef = useRef<HTMLElement>(null);
  const nav = currentUser.isSuperAdmin ? [...baseNav, ["users", "用户管理"] as [Page, string]] : baseNav;
  const onlineServers = useMemo(() => servers.filter((server) => server.status === "online").length, [servers]);
  const onlineClients = useMemo(() => clients.filter((client) => client.status === "online").length, [clients]);
  useEffect(() => {
    if (!showAccountMenu) return;
    const closeOutside = (event: PointerEvent) => {
      if (!accountAreaRef.current?.contains(event.target as Node)) setShowAccountMenu(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setShowAccountMenu(false);
    };
    document.addEventListener("pointerdown", closeOutside);
    document.addEventListener("keydown", closeOnEscape);
    return () => { document.removeEventListener("pointerdown", closeOutside); document.removeEventListener("keydown", closeOnEscape); };
  }, [showAccountMenu]);

  const loadData = async () => {
    setLoading(true);
    try {
      const [serverResponse, eventResponse] = await Promise.all([fetch("/api/v1/servers"), fetch("/api/v1/audit-logs?limit=5")]);
      if (!serverResponse.ok) throw new Error("无法获取服务端列表");
      const nextServers = await serverResponse.json() as Server[];
      setRecentEvents(eventResponse.ok ? await eventResponse.json() as AuditLog[] : []);
      setServers(nextServers);
      const grouped = await Promise.all(nextServers.map(async (server) => {
        const [clientResponse, mappingResponse] = await Promise.all([fetch(`/api/v1/servers/${server.id}/clients`), fetch(`/api/v1/servers/${server.id}/mappings`)]);
        const serverClients = clientResponse.ok ? await clientResponse.json() as Client[] : [];
        const serverMappings = mappingResponse.ok ? await mappingResponse.json() as Mapping[] : [];
        return { clients: serverClients, effectiveMappings: serverMappings.filter((mapping) => mapping.status === "effective").length };
      }));
      setClients(grouped.flatMap((group) => group.clients));
      setEffectiveMappings(grouped.reduce((total, group) => total + group.effectiveMappings, 0));
      setError("");
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "请求失败"); }
    finally { setLoading(false); }
  };
  useEffect(() => { void loadData(); const timer = window.setInterval(() => void loadData(), 10000); return () => window.clearInterval(timer); }, []);

  const createServer = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/servers", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: form.get("name"), endpoint: form.get("endpoint") }) });
      const payload = await response.json() as { server?: Server; error?: string };
      if (!response.ok || !payload.server) throw new Error(payload.error ?? "创建服务端失败");
      setShowServerForm(false); await loadData(); setPage("servers");
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "创建服务端失败"); }
  };

  const createClient = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const serverID = String(form.get("serverId"));
    try {
      const response = await fetch(`/api/v1/servers/${serverID}/clients`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: form.get("name") }) });
      const payload = await response.json() as { client?: Client; error?: string };
      if (!response.ok || !payload.client) throw new Error(payload.error ?? "创建客户端失败");
      setShowClientForm(false); await loadData(); setPage("clients");
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "创建客户端失败"); }
  };

  const downloadAgent = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!downloadTarget) return;
    const platform = String(new FormData(event.currentTarget).get("platform"));
    try {
      if (downloadTarget.role === "server") {
        const server = downloadTarget.server;
        await downloadPackage(`/api/v1/servers/${server.id}/download`, `matrix-tunnel-proxy-server-${server.id}.zip`, { platform });
      } else {
        const client = downloadTarget.client;
        await downloadPackage(`/api/v1/servers/${client.serverId}/clients/${client.id}/download`, `matrix-tunnel-proxy-client-${client.id}.zip`, { platform });
      }
      setDownloadTarget(null);
      await loadData();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "程序包下载失败"); }
  };

  const removeServer = async (server: Server) => {
    if (!window.confirm(`删除服务端“${server.name}”及其全部客户端和映射？`)) return;
    const response = await fetch(`/api/v1/servers/${server.id}`, { method: "DELETE" });
    if (!response.ok) { setError("删除服务端失败"); return; }
    await loadData();
  };

  const removeClient = async (client: Client) => {
    if (!window.confirm(`删除客户端“${client.name}”并立即撤销它的 Token？`)) return;
    const response = await fetch(`/api/v1/servers/${client.serverId}/clients/${client.id}`, { method: "DELETE" });
    if (!response.ok) { setError("删除客户端失败"); return; }
    await loadData();
  };

  const logout = async () => { await fetch("/api/v1/auth/logout", { method: "POST" }); onSignedOut(); };
  const roleName = currentUser.isSuperAdmin ? "超级管理员" : currentUser.isAdmin ? "管理员" : "普通用户";
  return <div className="app-shell"><aside><div className="brand"><span>{siteName.slice(0, 1).toUpperCase()}</span><div>{siteName}<small>控制中心</small></div></div><nav>{nav.map(([item, label]) => <button key={item} className={page === item ? "active" : ""} onClick={() => setPage(item)}>{label}</button>)}</nav><footer ref={accountAreaRef} className="account-area">{showAccountMenu && <div className="account-menu"><div className="account-menu-head"><strong>{currentUser.username}</strong><span>{roleName}</span></div><button onClick={() => { setShowAccountMenu(false); setShowPasswordForm(true); }}>修改密码</button><button className="account-logout" onClick={() => void logout()}>退出登录</button></div>}<button className="account-trigger" aria-expanded={showAccountMenu} onClick={() => setShowAccountMenu((visible) => !visible)}><span className="account-avatar">{currentUser.username.slice(0, 1).toUpperCase()}</span><span className="account-summary"><strong>{currentUser.username}</strong><small>{roleName}</small></span><span className="account-chevron">⌃</span></button></footer></aside><main>{error && <div className="alert">{error}<button onClick={() => setError("")}>关闭</button></div>}{page === "dashboard" && <Dashboard servers={servers} clients={clients} events={recentEvents} onlineServers={onlineServers} totalServers={servers.length} onlineClients={onlineClients} totalClients={clients.length} effectiveMappings={effectiveMappings} setPage={setPage} />}{page === "servers" && <Servers servers={servers} loading={loading} onCreate={() => setShowServerForm(true)} onDownload={(server) => setDownloadTarget({ role: "server", server })} onDelete={removeServer} />}{page === "clients" && <Clients servers={servers} clients={clients} loading={loading} onCreate={() => setShowClientForm(true)} onDownload={(client) => setDownloadTarget({ role: "client", client })} onDelete={removeClient} />}{page === "audit" && <Audit />}{page === "users" && currentUser.isSuperAdmin && <Users />}</main>{showServerForm && <ServerDialog onClose={() => setShowServerForm(false)} onSubmit={createServer} />}{showClientForm && <ClientDialog servers={servers} onClose={() => setShowClientForm(false)} onSubmit={createClient} />}{downloadTarget && <DownloadDialog target={downloadTarget} onClose={() => setDownloadTarget(null)} onSubmit={downloadAgent} />}{showPasswordForm && <OwnPasswordDialog onClose={() => setShowPasswordForm(false)} onChanged={onSignedOut} />}</div>;
}

function AuthScreen({ siteName, setup, loading = false, error: initialError, onAuthenticated }: { siteName: string; setup: boolean; loading?: boolean; error?: string; onAuthenticated: (user: User) => void }) {
  const [error, setError] = useState(initialError ?? "");
  const [submitting, setSubmitting] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setSubmitting(true); setError("");
    const form = new FormData(event.currentTarget);
    if (setup && form.get("password") !== form.get("confirmPassword")) { setError("两次输入的密码不一致"); setSubmitting(false); return; }
    try {
      const response = await fetch(setup ? "/api/v1/auth/setup" : "/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ siteName: form.get("siteName"), username: form.get("username"), password: form.get("password") }) });
      const payload = await response.json() as { user?: User; error?: string; lockedUntil?: string };
      if (!response.ok || !payload.user) throw new Error(payload.error ?? "登录失败");
      onAuthenticated(payload.user);
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "请求失败"); }
    finally { setSubmitting(false); }
  };
  return <div className="auth-shell"><div className="auth-brand"><span>{siteName.slice(0, 1).toUpperCase()}</span><strong>{siteName}</strong></div><form className="auth-card" onSubmit={submit}>{setup && <div className="setup-step">步骤 2 / 2 · SQLite 已就绪</div>}<h1>{setup ? "创建超级管理员" : "登录控制中心"}</h1><p>{setup ? "系统首次启动，请创建不可取消的默认超级管理员。" : `使用账号密码进入 ${siteName} 控制中心。`}</p>{error && <div className="auth-error">{error}</div>}{loading ? <div className="auth-loading">正在连接控制中心…</div> : <>{setup && <label>网站名称<input name="siteName" defaultValue="Matrix Tunnel Proxy" maxLength={64} required autoFocus /></label>}<label>用户名<input name="username" autoComplete="username" minLength={3} maxLength={64} required autoFocus={!setup} /></label><label>密码<input name="password" type="password" autoComplete={setup ? "new-password" : "current-password"} minLength={8} maxLength={256} required /></label>{setup && <label>确认密码<input name="confirmPassword" type="password" autoComplete="new-password" minLength={8} maxLength={256} required /></label>}<button className="primary auth-submit" disabled={submitting}>{submitting ? "请稍候…" : setup ? "创建并进入系统" : "登录"}</button></>}</form></div>;
}

function DatabaseSetupScreen({ siteName, onReady }: { siteName: string; onReady: () => void }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const initialize = async () => {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/v1/auth/database/setup", { method: "POST" });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "SQLite 初始化失败");
      onReady();
    } catch (requestError) { setError(requestError instanceof Error ? requestError.message : "SQLite 初始化失败"); }
    finally { setLoading(false); }
  };
  return <div className="auth-shell"><div className="auth-brand"><span>{siteName.slice(0, 1).toUpperCase()}</span><strong>{siteName}</strong></div><section className="auth-card database-setup"><div className="setup-step">步骤 1 / 2</div><h1>初始化 SQLite</h1><p>控制中心没有找到已初始化的数据库。SQLite 引擎已经包含在程序中，无需单独安装。</p>{error && <div className="auth-error">{error}</div>}<div className="database-info"><strong>将自动完成</strong><span>创建数据库文件和系统数据表</span><span>启用事务、外键和 WAL 模式</span><span>准备用户、服务端和审计数据</span></div><button className="primary auth-submit" disabled={loading} onClick={() => void initialize()}>{loading ? "正在初始化…" : "初始化 SQLite"}</button></section></div>;
}

function Users() {
  const [users, setUsers] = useState<User[]>([]);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const load = async () => { const response = await fetch("/api/v1/users"); const payload = await response.json() as User[] | { error?: string }; if (!response.ok || !Array.isArray(payload)) throw new Error(!Array.isArray(payload) ? payload.error : "无法加载用户"); setUsers(payload); };
  useEffect(() => { void load().catch((requestError) => setError(requestError.message)); }, []);
  const update = async (user: User, change: Record<string, unknown>) => {
    const response = await fetch(`/api/v1/users/${user.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(change) });
    const payload = await response.json().catch(() => ({})) as { error?: string };
    if (!response.ok) { setError(payload.error ?? "操作失败"); return; }
    await load();
  };
  const resetPassword = async (user: User) => { const password = window.prompt(`为“${user.username}”设置新密码（至少 8 个字符）`); if (password === null) return; await update(user, { password }); };
  return <><header><div><h1>用户管理</h1><p>只有超级管理员可以查看和管理用户。新用户默认是普通用户。</p></div><button className="primary" onClick={() => setShowCreate(true)}>创建用户</button></header>{error && <div className="alert">{error}<button onClick={() => setError("")}>关闭</button></div>}<section className="panel users-panel"><div className="user-head"><span>用户</span><span>角色</span><span>状态</span><span>操作</span></div>{users.map((user) => { const timedLocked = Boolean(user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now()); const locked = user.manualLocked || timedLocked; return <div className="user-row" key={user.id}><div><strong>{user.username}</strong><small>{user.id}</small></div><span>{user.isSuperAdmin ? <b className="role-badge super">超级管理员</b> : user.isAdmin ? <b className="role-badge admin">管理员</b> : <b className="role-badge">普通用户</b>}</span><span className={`status ${locked ? "locked" : "online"}`}>{locked ? user.manualLocked ? "已锁定" : "临时锁定" : "正常"}{user.failedAttempts > 0 && !locked ? ` · 失败 ${user.failedAttempts}/5` : ""}</span><span className="user-actions"><button className="compact" onClick={() => void resetPassword(user)}>修改密码</button>{!user.isSuperAdmin && <><button className="compact" onClick={() => void update(user, { isAdmin: !user.isAdmin })}>{user.isAdmin ? "取消管理员" : "设为管理员"}</button><button className={locked ? "compact" : "danger compact"} onClick={() => void update(user, { locked: !locked })}>{locked ? "解除锁定" : "锁定"}</button></>}</span></div>; })}</section>{showCreate && <CreateUserDialog onClose={() => setShowCreate(false)} onCreated={async () => { setShowCreate(false); await load(); }} />}</>;
}

function CreateUserDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); if (form.get("password") !== form.get("confirmPassword")) { setError("两次输入的密码不一致"); return; } const response = await fetch("/api/v1/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username: form.get("username"), password: form.get("password") }) }); const payload = await response.json() as { error?: string }; if (!response.ok) { setError(payload.error ?? "创建用户失败"); return; } onCreated(); };
  return <div className="modal-backdrop"><form className="modal" onSubmit={submit}><div className="modal-head"><h2>创建用户</h2><button type="button" className="link" onClick={onClose}>关闭</button></div>{error && <p className="form-error">{error}</p>}<label>用户名<input name="username" minLength={3} maxLength={64} required autoFocus /></label><label>初始密码<input name="password" type="password" minLength={8} maxLength={256} required /></label><label>确认密码<input name="confirmPassword" type="password" minLength={8} maxLength={256} required /></label><div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">创建</button></div></form></div>;
}

function OwnPasswordDialog({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const [error, setError] = useState("");
  const submit = async (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); if (form.get("newPassword") !== form.get("confirmPassword")) { setError("两次输入的新密码不一致"); return; } const response = await fetch("/api/v1/auth/password", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ currentPassword: form.get("currentPassword"), newPassword: form.get("newPassword") }) }); const payload = await response.json().catch(() => ({})) as { error?: string }; if (!response.ok) { setError(payload.error ?? "修改密码失败"); return; } onChanged(); };
  return <div className="modal-backdrop"><form className="modal" onSubmit={submit}><div className="modal-head"><h2>修改密码</h2><button type="button" className="link" onClick={onClose}>关闭</button></div>{error && <p className="form-error">{error}</p>}<label>当前密码<input name="currentPassword" type="password" required /></label><label>新密码<input name="newPassword" type="password" minLength={8} maxLength={256} required /></label><label>确认新密码<input name="confirmPassword" type="password" minLength={8} maxLength={256} required /></label><div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">确认修改</button></div></form></div>;
}

async function downloadPackage(url: string, filename: string, body: Record<string, FormDataEntryValue | string>) {
  const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (!response.ok) { const payload = await response.json() as { error?: string }; throw new Error(payload.error ?? "程序包下载失败"); }
  const blob = await response.blob(); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = filename; document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(link.href);
}

function Dashboard({ servers, clients, events, onlineServers, totalServers, onlineClients, totalClients, effectiveMappings, setPage }: { servers: Server[]; clients: Client[]; events: AuditLog[]; onlineServers: number; totalServers: number; onlineClients: number; totalClients: number; effectiveMappings: number; setPage: (page: Page) => void }) {
  const clientCounts = new Map<string, number>();
  for (const client of clients) clientCounts.set(client.serverId, (clientCounts.get(client.serverId) ?? 0) + 1);
  return <><header><div><h1>工作台</h1><p>查看服务端、客户端和映射的当前运行状态。</p></div></header><section className="stats"><Stat label="在线服务端" value={`${onlineServers} / ${totalServers}`} note="服务端通过加密连接上报状态" /><Stat label="在线客户端" value={`${onlineClients} / ${totalClients}`} note="客户端通过加密隧道保持连接" /><Stat label="生效映射" value={`${effectiveMappings}`} note="统计全部服务端当前生效的映射" /></section><section className="dashboard-grid"><article className="panel dashboard-servers"><div className="panel-head"><h2>服务端</h2>{servers.length > 5 && <button className="link" onClick={() => setPage("servers")}>查看更多</button>}</div>{servers.length === 0 ? <p className="empty">尚未创建服务端。</p> : servers.slice(0, 5).map((server) => <div className="dashboard-server-row" key={server.id}><div><strong>{server.name}</strong><small>{server.publicIps.length ? server.publicIps.join(" / ") : server.endpoint}</small></div><span className={`status ${server.status}`}>● {server.status === "online" ? "在线" : server.status === "offline" ? "离线" : "待激活"}</span><span>{clientCounts.get(server.id) ?? 0} 个客户端</span><button className="link" onClick={() => setPage("servers")}>管理</button></div>)}</article><article className="panel dashboard-events"><div className="panel-head"><h2>最新事件</h2></div>{events.length === 0 ? <p className="empty">暂无事件。</p> : events.slice(0, 5).map((event) => <div className="dashboard-event-row" key={event.id}><span className={`event-dot event-${event.action}`} /><div><strong>{auditEventTitle(event, servers, clients)}</strong><small>{relativeTime(event.createdAt)}</small></div></div>)}</article></section></>;
}

function auditEventTitle(event: AuditLog, servers: Server[], clients: Client[]) {
  const actions: Record<string, string> = { create: "创建", download: "下载", delete: "删除", priority: "调整优先级", firewall: "设置防火墙", rotate: "轮换" };
  const resources: Record<string, string> = { server: "服务端", client: "客户端", mapping: "映射", "server-certificate": "服务端证书" };
  const recordName = event.resourceType === "server" ? servers.find((server) => server.id === event.resourceId)?.name : event.resourceType === "client" ? clients.find((client) => client.id === event.resourceId)?.name : "";
  const detail = recordName || event.detail;
  return `${actions[event.action] ?? event.action}${resources[event.resourceType] ?? event.resourceType}${detail ? ` · ${detail}` : ""}`;
}

function relativeTime(value: string) {
  const elapsed = Math.max(0, Date.now() - new Date(value).getTime());
  const minutes = Math.floor(elapsed / 60000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  return `${days} 天前`;
}
function Servers({ servers, loading, onCreate, onDownload, onDelete }: { servers: Server[]; loading: boolean; onCreate: () => void; onDownload: (server: Server) => void; onDelete: (server: Server) => void }) { return <><header><div><h1>服务端</h1><p>每条记录对应一台公网服务器，创建记录后可随时单独下载程序包。</p></div><button className="primary" onClick={onCreate}>创建服务端</button></header><section className="panel"><div className="table-head"><span>名称</span><span>公网接入端点</span><span>状态</span><span>配置/操作</span></div>{loading ? <p className="empty">加载中…</p> : servers.length === 0 ? <p className="empty">尚未创建服务端。</p> : servers.map((server) => <div className="table-row" key={server.id}><div><strong>{server.name}</strong><small>{server.id}</small></div><span>{server.endpoint}</span><span className={`status ${server.status}`}>{server.status === "online" ? "在线" : server.status === "offline" ? "离线" : "待激活"}</span><span>v{server.configRevision} <button className="compact" onClick={() => onDownload(server)}>下载</button> <button className="danger compact" onClick={() => onDelete(server)}>删除</button></span></div>)}</section>{servers.length > 0 && <MappingManager servers={servers} />}</>; }

function MappingManager({ servers }: { servers: Server[] }) {
  const [serverID, setServerID] = useState(servers[0]?.id ?? "");
  const [clients, setClients] = useState<Client[]>([]);
  const [mappings, setMappings] = useState<Mapping[]>([]);
  const [message, setMessage] = useState("");
  const [mappingType, setMappingType] = useState<"port" | "full">("port");
  const [firewallMapping, setFirewallMapping] = useState<Mapping | null>(null);
  const [firewallError, setFirewallError] = useState("");
  const selectedServer = servers.find((server) => server.id === serverID);
  const canFullMap = selectedServer?.platform !== "darwin";
  const load = async (id: string) => {
    const [clientResponse, mappingResponse] = await Promise.all([fetch(`/api/v1/servers/${id}/clients`), fetch(`/api/v1/servers/${id}/mappings`)]);
    if (!clientResponse.ok || !mappingResponse.ok) throw new Error("无法加载映射配置");
    setClients(await clientResponse.json() as Client[]); setMappings(await mappingResponse.json() as Mapping[]);
  };
  useEffect(() => { if (!servers.some((server) => server.id === serverID)) setServerID(servers[0]?.id ?? ""); }, [servers, serverID]);
  useEffect(() => { if (!canFullMap && mappingType === "full") setMappingType("port"); }, [canFullMap, mappingType]);
  useEffect(() => { if (serverID) void load(serverID).catch((error) => setMessage(error.message)); }, [serverID]);
  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const formElement = event.currentTarget; const form = new FormData(formElement);
    const response = await fetch(`/api/v1/servers/${serverID}/mappings`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ clientId: form.get("clientId"), mappingType: form.get("mappingType"), protocol: form.get("protocol"), publicIp: form.get("publicIp"), publicPort: Number(form.get("publicPort")), targetHost: form.get("targetHost"), targetPort: Number(form.get("targetPort")), excludedPorts: form.get("excludedPorts"), priority: Number(form.get("priority")) }) });
    const payload = await response.json() as { error?: string };
    if (!response.ok) { setMessage(payload.error ?? "创建映射失败"); return; }
    setMessage("映射已保存，服务端下次拉取配置后生效。"); await load(serverID); formElement.reset();
  };
  const remove = async (mapping: Mapping) => {
    if (!window.confirm(`删除映射 ${mapping.publicIp}:${mapping.publicPort}？`)) return;
    const response = await fetch(`/api/v1/servers/${serverID}/mappings/${mapping.id}`, { method: "DELETE" });
    if (!response.ok) { setMessage("删除映射失败"); return; }
    setMessage("映射已删除。"); await load(serverID);
  };
  const setPriority = async (mapping: Mapping, priority: number) => {
    const response = await fetch(`/api/v1/servers/${serverID}/mappings/${mapping.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ priority }) });
    if (!response.ok) { setMessage("修改优先级失败"); return; }
    setMessage(`优先级已调整为 ${priority}。`); await load(serverID);
  };
  const saveFirewall = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!firewallMapping) return;
    const form = new FormData(event.currentTarget);
    const response = await fetch(`/api/v1/servers/${serverID}/mappings/${firewallMapping.id}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ accessMode: form.get("accessMode"), allowedIps: form.get("allowedIps") }) });
    const payload = await response.json().catch(() => ({})) as { error?: string };
    if (!response.ok) { setFirewallError(payload.error ?? "防火墙设置保存失败"); return; }
    setFirewallError(""); setFirewallMapping(null); setMessage("防火墙设置已保存，服务端下次拉取配置后生效。"); await load(serverID);
  };
  return <><section className="panel mapping-panel">
    <div className="panel-head"><h2>映射配置</h2><select value={serverID} onChange={(event) => setServerID(event.target.value)}>{servers.map((server) => <option value={server.id} key={server.id}>{server.name}</option>)}</select></div>
    {message && <p className="mapping-message">{message}</p>}
    {clients.length === 0 ? <p className="empty">请先在这台服务端下创建客户端。</p> : <form className="mapping-form" onSubmit={create}>
      <label>客户端<select name="clientId">{clients.map((client) => <option value={client.id} key={client.id}>{client.name}</option>)}</select></label>
      <label>映射方式<select name="mappingType" value={mappingType} onChange={(event) => setMappingType(event.target.value as "port" | "full")}><option value="port">端口映射</option><option value="full" disabled={!canFullMap}>全映射 TCP+UDP{!canFullMap ? "（该服务端不支持）" : ""}</option></select></label>
      {mappingType === "port" && <label>协议<select name="protocol"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>}
      <label>绑定 IP<select name="publicIp" required><option value="">选择网卡 IP</option>{mappingType === "port" && <option value="0.0.0.0">全部网卡</option>}{(selectedServer?.publicIps ?? []).map((ip) => <option value={ip} key={ip}>{ip}</option>)}</select></label>
      {mappingType === "port" && <label>公网端口<input name="publicPort" type="number" min="1" max="65535" required /></label>}
      <label>目标地址<input name="targetHost" defaultValue="127.0.0.1" required /></label>
      {mappingType === "port" ? <label>目标端口<input name="targetPort" type="number" min="1" max="65535" required /></label> : <label>保留端口<input name="excludedPorts" placeholder="22,3389,8000-8010" /><small>隧道端口自动保留</small></label>}
      <label>优先级<input name="priority" type="number" defaultValue="0" /></label>
      <button className="primary">添加映射</button>
    </form>}
    <div className="mapping-list">{mappings.length === 0 ? <p className="empty">暂无映射。</p> : mappings.map((mapping) => <div className="mapping-row" key={mapping.id}>
      <strong>{mapping.mappingType === "full" ? `全映射 · ${mapping.publicIp}` : `${mapping.protocol.toUpperCase()} · ${mapping.publicIp}:${mapping.publicPort}`}</strong>
      <span>{mapping.mappingType === "full" ? `→ ${mapping.targetHost} · 保留 ${mapping.excludedPorts || "无"}` : `→ ${mapping.targetHost}:${mapping.targetPort}`}</span>
      <span>优先级 {mapping.priority} <button className="compact" onClick={() => void setPriority(mapping, mapping.priority + 1)}>＋</button><button className="compact" onClick={() => void setPriority(mapping, mapping.priority - 1)}>－</button></span>
      <span className="mapping-access">{mapping.accessMode === "allowlist" ? `仅限 ${mapping.allowedIps}` : "公开访问"}</span>
      <span className={`status ${mapping.status === "effective" ? "online" : ""}`}>{mapping.status === "effective" ? "生效" : "被占用"} <button className="compact" onClick={() => { setFirewallError(""); setFirewallMapping(mapping); }}>防火墙</button><button className="danger compact" onClick={() => void remove(mapping)}>删除</button></span>
    </div>)}</div>
  </section>{firewallMapping && <FirewallDialog mapping={firewallMapping} error={firewallError} onClose={() => setFirewallMapping(null)} onSubmit={saveFirewall} />}</>;
}

function FirewallDialog({ mapping, error, onClose, onSubmit }: { mapping: Mapping; error: string; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) {
  const [mode, setMode] = useState<"public" | "allowlist">(mapping.accessMode || "public");
  return <div className="modal-backdrop"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><h2>映射防火墙</h2><button type="button" className="link" onClick={onClose}>关闭</button></div><p className="modal-note">{mapping.mappingType === "full" ? mapping.publicIp : `${mapping.protocol.toUpperCase()} ${mapping.publicIp}:${mapping.publicPort}`}</p>{error && <p className="form-error">{error}</p>}<label>访问方式<select name="accessMode" value={mode} onChange={(event) => setMode(event.target.value as "public" | "allowlist")}><option value="public">公开访问</option><option value="allowlist">仅允许指定 IP</option></select></label>{mode === "allowlist" && <label>允许访问的 IP 或网段<textarea name="allowedIps" defaultValue={mapping.allowedIps?.replaceAll(",", "\n")} placeholder={"203.0.113.10\n198.51.100.0/24\n2001:db8::/32"} required /><small>每行一个，也可用逗号分隔；支持 IPv4、IPv6 和 CIDR 网段。</small></label>}<div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">保存设置</button></div></form></div>;
}
function Clients({ servers, clients, loading, onCreate, onDownload, onDelete }: { servers: Server[]; clients: Client[]; loading: boolean; onCreate: () => void; onDownload: (client: Client) => void; onDelete: (client: Client) => void }) { const names = new Map(servers.map((server) => [server.id, server.name])); return <><header><div><h1>客户端</h1><p>创建客户端记录后可单独下载绑定包，无须手动填写连接信息。</p></div><button className="primary" disabled={!servers.length} onClick={onCreate}>创建客户端</button></header><section className="panel"><div className="table-head"><span>名称</span><span>绑定服务端</span><span>平台</span><span>状态/操作</span></div>{loading ? <p className="empty">加载中…</p> : clients.length === 0 ? <p className="empty">{servers.length ? "还没有客户端，请先创建客户端记录。" : "请先创建服务端。"}</p> : clients.map((client) => <div className="table-row" key={client.id}><div><strong>{client.name}</strong><small>{client.id}</small></div><span>{names.get(client.serverId) ?? client.serverId}</span><span>{client.platform === "pending" ? "未下载" : client.platform}</span><span className={`status ${client.status}`}>{client.status === "online" ? "在线" : "离线"} <button className="compact" onClick={() => onDownload(client)}>下载</button> <button className="danger compact" onClick={() => onDelete(client)}>删除</button></span></div>)}</section></>; }
function Audit() {
  const [items, setItems] = useState<AuditLog[]>([]);
  const [error, setError] = useState("");
  const load = async () => { const response = await fetch("/api/v1/audit-logs?limit=200"); if (!response.ok) throw new Error("无法加载审计日志"); setItems(await response.json() as AuditLog[]); };
  useEffect(() => { void load().catch((requestError) => setError(requestError.message)); }, []);
  const actionName: Record<string, string> = { create: "创建", download: "下载", delete: "删除", priority: "调整优先级", firewall: "设置防火墙", rotate: "轮换证书" };
  const resourceName: Record<string, string> = { server: "服务端", client: "客户端", mapping: "映射" };
  return <><header><div><h1>审计日志</h1><p>创建、下载、配置变更和撤销操作都会留痕。</p></div><button onClick={() => void load()}>刷新</button></header><section className="panel"><div className="audit-head"><span>时间</span><span>操作</span><span>资源</span><span>详情</span></div>{error ? <p className="empty">{error}</p> : items.length === 0 ? <p className="empty">暂无审计记录。</p> : items.map((item) => <div className="audit-row" key={item.id}><span>{new Date(item.createdAt).toLocaleString()}</span><strong>{actionName[item.action] ?? item.action}</strong><span>{resourceName[item.resourceType] ?? item.resourceType}<small>{item.resourceId}</small></span><span>{item.detail || "—"}</span></div>)}</section></>;
}
function Stat({ label, value, note }: { label: string; value: string; note: string }) { return <article className="stat"><span>{label}</span><strong>{value}</strong><small>{note}</small></article>; }
function PlatformSelect({ defaultValue = "windows-amd64" }: { defaultValue?: string }) { return <select name="platform" defaultValue={defaultValue}><option value="windows-amd64">Windows x64</option><option value="linux-amd64">Linux x64</option><option value="linux-arm64">Linux ARM64</option><option value="darwin-amd64">macOS Intel</option><option value="darwin-arm64">macOS Apple Silicon</option></select>; }
function ServerDialog({ onClose, onSubmit }: { onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) { return <div className="modal-backdrop" role="presentation"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><h2>创建服务端</h2><button type="button" className="link" onClick={onClose}>关闭</button></div><label>名称<input required name="name" placeholder="edge-sh-01" /></label><label>公网接入端点<input required name="endpoint" placeholder="edge-sh.example.com:7000" /></label><div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">创建</button></div></form></div>; }
function ClientDialog({ servers, onClose, onSubmit }: { servers: Server[]; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) { return <div className="modal-backdrop" role="presentation"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><h2>创建客户端</h2><button type="button" className="link" onClick={onClose}>关闭</button></div><label>绑定服务端<select required name="serverId">{servers.map((server) => <option value={server.id} key={server.id}>{server.name} - {server.endpoint}</option>)}</select></label><label>名称<input required name="name" placeholder="office-pc-01" /></label><div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">创建</button></div></form></div>; }
function DownloadDialog({ target, onClose, onSubmit }: { target: DownloadTarget; onClose: () => void; onSubmit: (event: FormEvent<HTMLFormElement>) => void }) { const name = target.role === "server" ? target.server.name : target.client.name; const defaultPlatform = target.role === "client" && target.client.platform !== "pending" ? target.client.platform : "windows-amd64"; return <div className="modal-backdrop" role="presentation"><form className="modal" onSubmit={onSubmit}><div className="modal-head"><h2>下载{name}程序包</h2><button type="button" className="link" onClick={onClose}>关闭</button></div><label>目标平台<PlatformSelect defaultValue={defaultPlatform} /></label><div className="modal-foot"><button type="button" onClick={onClose}>取消</button><button className="primary">下载</button></div></form></div>; }
