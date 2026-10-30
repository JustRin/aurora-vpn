import { readText } from "@tauri-apps/plugin-clipboard-manager";
import {
  ClipboardPaste,
  Cloud,
  Copy,
  EllipsisVertical,
  Gauge,
  GripVertical,
  Pencil,
  Plus,
  RefreshCw,
  Server as ServerIcon,
  Trash2,
} from "lucide-react";
import { useCallback, useState } from "react";

import { FreePoolButton } from "../components/FreePool";
import { QrSources } from "../components/QrScanner";
import { OwnServersHead, SubscriptionCard } from "../components/SubscriptionCard";
import { Empty, Field, Modal, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { BALANCERS, balancerMeta, onBackup } from "../lib/balancers";
import { latencyTier, masqueHttp2, protocolLabel, transportLabel } from "../lib/format";
import { applyOrder, useReorder } from "../lib/reorder";
import { tNow, useT } from "../lib/i18n";
import {
  type ImportReport,
  type Network,
  type Protocol,
  type Security,
  type ServerNode,
  shownServerId,
} from "../lib/types";
import { useStore } from "../store";

const PROTOCOLS: Protocol[] = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "hysteria2",
  "tuic",
  "masque",
];
const NETWORKS: Network[] = ["tcp", "ws", "grpc", "http", "httpupgrade"];
const SECURITIES: Security[] = ["none", "tls", "reality"];

function emptyNode(): ServerNode {
  return {
    id: "",
    name: "",
    protocol: "vless",
    address: "",
    port: 443,
    uuid: "",
    password: "",
    method: "aes-256-gcm",
    alterId: 0,
    vmessSecurity: "auto",
    network: "tcp",
    path: "",
    host: "",
    serviceName: "",
    security: "reality",
    sni: "",
    alpn: [],
    fingerprint: "chrome",
    publicKey: "",
    shortId: "",
    allowInsecure: false,
    flow: "xtls-rprx-vision",
    mux: false,
    obfs: "",
    obfsPassword: "",
    hopPorts: [],
    privateKey: "",
    peerPublicKey: "",
    localV4: "",
    localV6: "",
    reserved: [],
    mtu: 1280,
    keepalive: 30,
    preSharedKey: "",
    username: "",
    subscriptionId: null,
    rawLink: "",
  };
}

export function Servers() {
  const t = useT();
  const nodes = useStore((s) => s.nodes);
  const subs = useStore((s) => s.subscriptions);
  const status = useStore((s) => s.status);
  const balancer = useStore((s) => s.settings.balancer ?? "manual");
  const saveSettings = useStore((s) => s.saveSettings);
  // Exactly one row is highlighted across both sections: the balancer while
  // it decides, else the server carrying traffic. Under a balancer the routed
  // server only gets a «now» marker.
  const shownId = shownServerId(status);
  const activeId = balancer === "manual" ? shownId : "";
  const routedId = balancer === "manual" ? "" : shownId;
  const backup = onBackup(balancer, status);
  const testing = useStore((s) => s.busy.latency);
  const openGroups = useStore((s) => s.openGroups);
  const setOpenGroups = useStore((s) => s.setOpenGroups);
  const refreshLatency = useStore((s) => s.refreshLatency);
  const reload = useStore((s) => s.reload);
  const toast = useStore((s) => s.toast);

  const [importOpen, setImportOpen] = useState(false);
  const [refreshingAll, setRefreshingAll] = useState(false);
  const [editing, setEditing] = useState<ServerNode | null>(null);
  const [addingWarp, setAddingWarp] = useState(false);
  // Сервер, чьи действия открыты кнопкой «⋮» — так их достают на сенсорном
  // экране, где наведения, открывающего кнопки в строке, не бывает.
  const [actionsFor, setActionsFor] = useState<ServerNode | null>(null);

  /** WARP as a server of its own, for when there is no server to wrap.
   *  A second one would be pointless — both would share the single session
   *  Cloudflare allows — so the backend refreshes the existing one instead. */
  async function addWarp() {
    setAddingWarp(true);
    try {
      await api.addWarpNode();
      await reload();
      toast("success", t("srv.warpAdded"));
    } catch (e) {
      toast("error", t("srv.warpFailed"), errText(e));
    } finally {
      setAddingWarp(false);
    }
  }

  async function remove(node: ServerNode) {
    try {
      await api.deleteServer(node.id);
      toast("info", t("srv.serverDeleted", { name: node.name }));
    } catch (e) {
      toast("error", t("srv.deleteFailed"), errText(e));
    }
  }

  async function copyLink(node: ServerNode) {
    if (!node.rawLink) {
      toast("info", t("srv.noRawLink"));
      return;
    }
    await navigator.clipboard.writeText(node.rawLink);
    toast("success", t("srv.linkCopied"));
  }

  // Узел, чья подписка уже удалена, считается своим — иначе он пропал бы с
  // экрана, оставшись в списке. Своих обычно единицы, они идут последними.
  const known = new Set(subs.map((sub) => sub.id));
  const groupOf = (node: ServerNode) =>
    node.subscriptionId && known.has(node.subscriptionId) ? node.subscriptionId : "";
  const nodesOf = (id: string) => nodes.filter((node) => groupOf(node) === id);
  const own = nodesOf("");

  // Пока разделы не трогали, открыт тот, где лежит текущий сервер. Первый же
  // щелчок отменяет автоматику: дальше список открыт так, как его оставили.
  const shownNode = nodes.find((node) => node.id === shownId);
  const shownGroup = shownNode ? groupOf(shownNode) : "";
  const isOpen = (id: string) => (openGroups ? openGroups.includes(id) : id === shownGroup);
  const toggleGroup = (id: string) => {
    const current = openGroups ?? [shownGroup];
    setOpenGroups(current.includes(id) ? current.filter((g) => g !== id) : [...current, id]);
  };

  const rows = (group: ServerNode[]) => (
    <ServerRows
      nodes={group}
      activeId={activeId}
      routedId={routedId}
      onCopy={(node) => void copyLink(node)}
      onEdit={setEditing}
      onRemove={(node) => void remove(node)}
      onMore={setActionsFor}
    />
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t("srv.title")}</h1>
          <p className="page-sub">
            {t("srv.subtitleBefore")} <span className="mono">vless://</span>{" "}
            {t("srv.subtitleAfter")}
          </p>
        </div>
        <div className="row">
          <button
            type="button"
            className="btn"
            disabled={testing || nodes.length === 0}
            onClick={() => void refreshLatency()}
          >
            <Gauge size={15} className={testing ? "spin" : ""} />
            {t("srv.testLatency")}
          </button>
          <button
            type="button"
            className="btn"
            disabled={addingWarp}
            title={t("srv.addWarpTitle")}
            onClick={() => void addWarp()}
          >
            <Cloud size={15} className={addingWarp ? "spin" : ""} />
            WARP
          </button>
          <FreePoolButton onReport={(report) => reportToast(report, toast)} />
          <button
            type="button"
            className="btn primary"
            onClick={() => setImportOpen(true)}
          >
            <Plus size={15} />
            {t("srv.addBtn")}
          </button>
        </div>
      </div>

      {/* The strategies sit in the same list as the servers, as separate
          entries — the way Hiddify lists its «Auto» group — so they are seen
          and switched on with the same gesture. One server leaves nothing to
          choose from, so the section appears from the second. */}
      {nodes.length >= 2 && (
        <>
          <div className="section-title">{t("pick.balancers")}</div>
          <div className="list">
            {BALANCERS.map((entry) => {
              const on = balancer === entry.id;
              const alarmed = on && backup;
              const Icon = entry.icon;
              return (
                <div
                  key={entry.id}
                  className={`node${on ? " active" : ""}`}
                  onDoubleClick={() => void saveSettings({ balancer: entry.id })}
                >
                  <button
                    type="button"
                    className="node-radio"
                    aria-label={t(entry.label)}
                    onClick={() => void saveSettings({ balancer: entry.id })}
                  />
                  <span className={`node-icon ${alarmed ? "warn" : "balancer"}`}>
                    <Icon size={16} />
                  </span>
                  <div className="grow" style={{ minWidth: 0 }}>
                    <div className="node-name truncate">{t(entry.label)}</div>
                    <div className={`node-meta${alarmed ? " warn" : ""}`}>
                      <span className="truncate">
                        {balancerMeta(t, entry, balancer, status, nodes)}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}

      <div className="row between" style={{ margin: "30px 0 11px" }}>
        <div className="section-title" style={{ margin: 0 }}>
          {t("srv.title")} {nodes.length > 0 && <span>({nodes.length})</span>}
        </div>
        {subs.length > 0 && (
          <button
            type="button"
            className="btn ghost sm"
            disabled={refreshingAll}
            onClick={async () => {
              setRefreshingAll(true);
              try {
                reportToast(await api.refreshAllSubscriptions(), toast);
              } catch (e) {
                toast("error", t("srv.refreshFailed"), errText(e));
              } finally {
                setRefreshingAll(false);
              }
            }}
          >
            <RefreshCw size={14} className={refreshingAll ? "spin" : ""} />
            {t("srv.refreshAll")}
          </button>
        )}
      </div>

      {nodes.length === 0 && subs.length === 0 ? (
        <Empty
          icon={<ServerIcon size={34} color="var(--text-muted)" />}
          title={t("srv.emptyTitle")}
          text={t("srv.emptyText")}
          action={
            <button
              type="button"
              className="btn primary"
              onClick={() => setImportOpen(true)}
            >
              <Plus size={15} />
              {t("srv.pasteLinks")}
            </button>
          }
        />
      ) : subs.length === 0 ? (
        // Без подписок раздел был бы один: сворачивать нечего и незачем.
        rows(nodes)
      ) : (
        <div className="server-groups">
          {subs.map((sub) => (
            <section key={sub.id} className="server-group">
              <SubscriptionCard
                sub={sub}
                open={isOpen(sub.id)}
                onToggle={() => toggleGroup(sub.id)}
                onDelete={async () => {
                  await api.deleteSubscription(sub.id);
                  await reload();
                }}
              />
              {isOpen(sub.id) && rows(nodesOf(sub.id))}
            </section>
          ))}
          {own.length > 0 && (
            <section className="server-group">
              <OwnServersHead
                count={own.length}
                open={isOpen("")}
                onToggle={() => toggleGroup("")}
              />
              {isOpen("") && rows(own)}
            </section>
          )}
        </div>
      )}

      <Modal
        open={actionsFor !== null}
        title={actionsFor?.name ?? ""}
        onClose={() => setActionsFor(null)}
      >
        {actionsFor && (
          <div className="action-list">
            <button
              type="button"
              className="picker-item"
              onClick={() => {
                setActionsFor(null);
                void copyLink(actionsFor);
              }}
            >
              <Copy size={16} />
              {t("srv.copyLinkTitle")}
            </button>
            <button
              type="button"
              className="picker-item"
              onClick={() => {
                setActionsFor(null);
                setEditing(actionsFor);
              }}
            >
              <Pencil size={16} />
              {t("srv.editTitle")}
            </button>
            <button
              type="button"
              className="picker-item danger"
              onClick={() => {
                setActionsFor(null);
                void remove(actionsFor);
              }}
            >
              <Trash2 size={16} />
              {t("srv.deleteTitle")}
            </button>
          </div>
        )}
      </Modal>

      <ImportModal open={importOpen} onClose={() => setImportOpen(false)} />
      {editing && (
        // Keying on the node id remounts the form, so its draft state is seeded
        // from the freshly selected node instead of leaking between edits.
        <NodeEditor
          key={editing.id || "new"}
          node={editing}
          onClose={() => setEditing(null)}
        />
      )}

      <div className="row" style={{ marginTop: 20, justifyContent: "center" }}>
        <button
          type="button"
          className="btn ghost sm"
          onClick={() => setEditing(emptyNode())}
        >
          <Plus size={14} />
          {t("srv.addManually")}
        </button>
      </div>
    </>
  );
}

/**
 * Строки одного раздела. Перетаскивают их только внутри него: раздел — это
 * панель, которая сервер раздаёт, и сменить её перетаскиванием нельзя.
 */
function ServerRows({
  nodes,
  activeId,
  routedId,
  onCopy,
  onEdit,
  onRemove,
  onMore,
}: {
  nodes: ServerNode[];
  activeId: string;
  routedId: string;
  onCopy: (node: ServerNode) => void;
  onEdit: (node: ServerNode) => void;
  onRemove: (node: ServerNode) => void;
  onMore: (node: ServerNode) => void;
}) {
  const t = useT();
  const latency = useStore((s) => s.latency);
  const selectServer = useStore((s) => s.selectServer);
  const reload = useStore((s) => s.reload);
  const toast = useStore((s) => s.toast);

  /** Новый порядок уезжает на бэкенд один раз, когда строку отпустили. Бэкенду
   *  нужен весь список: узлы раздела встают на те же места, что и занимали. */
  const saveOrder = useCallback(
    async (ids: string[]) => {
      const moved = new Set(ids);
      let next = 0;
      const all = useStore
        .getState()
        .nodes.map((node) => (moved.has(node.id) ? ids[next++] : node.id));
      try {
        await api.reorderServers(all);
      } catch (e) {
        toast("error", tNow("srv.reorderFailed"), errText(e));
        // Порядок на экране был предположением: вернуть тот, что на диске.
        await reload();
      }
    },
    [reload, toast],
  );
  const reorder = useReorder(
    nodes.map((n) => n.id),
    saveOrder,
  );
  const ordered = applyOrder(nodes, reorder.order);

  return (
    <div className="list" data-reorder-list>
      {ordered.map((node) => {
        const ms = latency[node.id];
        const tier = latencyTier(ms);
        const held = reorder.dragging === node.id;
        return (
          <div
            key={node.id}
            data-reorder-id={node.id}
            className={`node${node.id === activeId ? " active" : ""}${held ? " dragging" : ""}`}
            onDoubleClick={() => void selectServer(node.id)}
          >
            {/* Тянуть за отдельную ручку, а не за строку: строка занята
                двойным щелчком, кнопками и прокруткой пальцем. */}
            <span
              className="node-grip"
              role="button"
              tabIndex={-1}
              aria-label={t("srv.reorderHandle")}
              title={t("srv.reorderHandle")}
              {...reorder.gripProps(node.id)}
            >
              <GripVertical size={15} />
            </span>
            <button
              type="button"
              className="node-radio"
              aria-label={t("srv.selectServer")}
              onClick={() => void selectServer(node.id)}
            />
            {/* The muted server icon pairs with the accent strategy icon in
                the same column: the two kinds of row read differently at
                a glance. */}
            <span className="node-icon">
              <ServerIcon size={16} />
            </span>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="node-name truncate">{node.name}</div>
              <div className="node-meta">
                {node.id === routedId && (
                  <span className="chip accent">{t("pick.nowChip")}</span>
                )}
                <span className="chip">{protocolLabel(node.protocol)}</span>
                <span className="truncate">
                  {transportLabel(node.security, node.network, node.protocol, node.alpn)}
                </span>
                {/* Точка — в одном куске с адресом: на телефоне адрес
                    ужимается первым, и она уходит вместе с ним, а не
                    висит в конце строки. */}
                <span className="truncate">
                  {"· "}
                  {node.address}:{node.port}
                </span>
              </div>
            </div>

            <span className={`dot ${tier}`} />
            <span className="latency">
              {ms === undefined ? "—" : ms === null ? t("srv.latencyNa") : t("srv.latencyMs", { ms })}
            </span>

            <div className="node-actions">
              <button
                type="button"
                className="btn ghost icon"
                title={t("srv.copyLinkTitle")}
                onClick={() => onCopy(node)}
              >
                <Copy size={14} />
              </button>
              <button
                type="button"
                className="btn ghost icon"
                title={t("srv.editTitle")}
                onClick={() => onEdit(node)}
              >
                <Pencil size={14} />
              </button>
              <button
                type="button"
                className="btn ghost icon"
                title={t("srv.deleteTitle")}
                onClick={() => onRemove(node)}
              >
                <Trash2 size={14} />
              </button>
            </div>
            {/* Вместо трёх кнопок на сенсорном экране (см. .node-more):
                они ждут наведения, и, невидимые, всё равно съедали
                ширину — на телефоне имя сервера сжималось до буквы. */}
            <button
              type="button"
              className="btn ghost icon node-more"
              aria-label={t("srv.moreActions")}
              onClick={() => onMore(node)}
            >
              <EllipsisVertical size={16} />
            </button>
          </div>
        );
      })}
    </div>
  );
}

type ToastFn = (kind: "info" | "success" | "error", text: string, detail?: string) => void;

function reportToast(report: ImportReport, toast: ToastFn) {
  const parts: string[] = [];
  if (report.added) parts.push(tNow("srv.reportAdded", { n: report.added }));
  if (report.skipped) parts.push(tNow("srv.reportSkipped", { n: report.skipped }));

  if (report.errors.length > 0) {
    // Surface the reason, not just a count — a rejected transport is actionable.
    const detail = report.errors
      .slice(0, 5)
      .map(([line, reason]) => `${reason}\n${line}`)
      .join("\n\n");
    const summary = parts.join(", ") || tNow("srv.reportNothing");
    toast(
      report.added ? "info" : "error",
      `${summary} · ${tNow("srv.reportErrors", { n: report.errors.length })}`,
      detail,
    );
    return;
  }
  toast(report.added ? "success" : "info", parts.join(", ") || tNow("srv.reportNoNew"));
}

function ImportModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const t = useT();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useStore((s) => s.toast);
  const reload = useStore((s) => s.reload);

  /**
   * A code that has been read joins whatever is already in the box, one per
   * line. It is not imported straight away on purpose: the user sees what the
   * scanner made of the picture, and can scan a second code before importing
   * both at once.
   */
  function addScanned(found: string[]) {
    setText((current) => {
      const present = current.split("\n").map((line) => line.trim());
      const fresh = found
        .map((one) => one.trim())
        .filter((one) => one && !present.includes(one));
      if (fresh.length === 0) return current;
      const head = current.trimEnd();
      return head ? `${head}\n${fresh.join("\n")}` : fresh.join("\n");
    });
  }

  /** Straight from the clipboard, without having to find the box first. */
  async function paste() {
    try {
      const clipboard = await readText();
      if (!clipboard?.trim()) {
        toast("info", t("srv.clipboardEmpty"));
        return;
      }
      addScanned(clipboard.split("\n"));
    } catch (e) {
      toast("error", t("srv.pasteFailed"), errText(e));
    }
  }

  async function submit() {
    setBusy(true);
    try {
      const report = await api.addLinks(text);
      reportToast(report, toast);
      await reload();
      if (report.added > 0) {
        setText("");
        onClose();
      }
    } catch (e) {
      toast("error", t("srv.importFailed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      title={t("srv.addServers")}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("srv.cancel")}
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={busy || !text.trim()}
            onClick={() => void submit()}
          >
            {t("srv.importBtn")}
          </button>
        </>
      }
    >
      <Field label={t("srv.linksLabel")} hint={t("srv.linksHint")}>
        <textarea
          className="textarea"
          style={{ minHeight: 190 }}
          placeholder={t("srv.linkPlaceholder")}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </Field>
      <div className="qr-sources">
        <button type="button" className="btn sm" onClick={() => void paste()}>
          <ClipboardPaste size={14} />
          {t("srv.pasteBtn")}
        </button>
        {/* What goes into the box as it is, and what has to be read off a
            picture first, are two different gestures on one row. */}
        <span className="qr-sources-sep" aria-hidden="true" />
        <QrSources onFound={addScanned} />
      </div>
    </Modal>
  );
}


function NodeEditor({
  node,
  onClose,
}: {
  node: ServerNode;
  onClose: () => void;
}) {
  const t = useT();
  const [current, setCurrent] = useState<ServerNode>(node);
  const toast = useStore((s) => s.toast);
  const reload = useStore((s) => s.reload);

  const set = (patch: Partial<ServerNode>) => setCurrent({ ...current, ...patch });
  const isNew = current.id === "";
  const needsUuid = ["vless", "vmess", "tuic"].includes(current.protocol);
  const needsPassword = ["trojan", "shadowsocks", "hysteria2", "tuic", "masque"].includes(
    current.protocol,
  );
  // WireGuard is its own encryption and carries no transport, so every field
  // below the address describes something that is not there. Its keys are not
  // shown either: they belong to the Cloudflare account, which is managed from
  // the settings rather than typed in by hand.
  const isWireguard = current.protocol === "wireguard";
  // AmneziaWG likewise: keys and obfuscation come from the server's config as
  // one set, and a hand-edited half of it only breaks the handshake.
  const isAwg = current.protocol === "amneziawg";
  const lockedProtocol = isWireguard || isAwg;
  // MASQUE has a transport of its own and is always TLS.
  const isMasque = current.protocol === "masque";
  const hasTransport = !["hysteria2", "tuic", "wireguard", "amneziawg", "masque"].includes(
    current.protocol,
  );

  async function save() {
    try {
      if (isNew) {
        // Round-trip through the link parser so a hand-built node goes through
        // exactly the same validation as an imported one.
        const report = await api.addLinks(buildLink(current));
        if (report.added === 0) {
          // Report the parser's own reason (missing REALITY key, bad transport…)
          // rather than claiming success over a node that was never stored.
          toast(
            "error",
            t("srv.serverNotAdded"),
            report.errors[0]?.[1] ?? t("srv.duplicateServer"),
          );
          return;
        }
        toast("success", t("srv.serverAdded"));
      } else {
        await api.updateServer(current);
        toast("success", t("srv.serverSaved"));
      }
      await reload();
      onClose();
    } catch (e) {
      toast("error", t("srv.saveFailed"), errText(e));
    }
  }

  return (
    <Modal
      open
      wide
      title={isNew ? t("srv.newServer") : t("srv.serverParams")}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("srv.cancel")}
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={!current.address || !current.name}
            onClick={() => void save()}
          >
            {t("srv.saveBtn")}
          </button>
        </>
      }
    >
      <div className="grid-2">
        <Field label={t("srv.nameLabel")}>
          <input
            className="input"
            value={current.name}
            onChange={(e) => set({ name: e.target.value })}
          />
        </Field>
        <Field label={t("srv.protocolLabel")}>
          <select
            className="select"
            value={current.protocol}
            disabled={lockedProtocol}
            onChange={(e) => set({ protocol: e.target.value as Protocol })}
          >
            {(lockedProtocol ? [current.protocol] : PROTOCOLS).map((p) => (
              <option key={p} value={p}>
                {protocolLabel(p)}
              </option>
            ))}
          </select>
        </Field>
        <Field label={t("srv.addressLabel")}>
          <input
            className="input"
            value={current.address}
            onChange={(e) => set({ address: e.target.value })}
            placeholder="example.com"
          />
        </Field>
        <Field label={t("srv.portLabel")}>
          <input
            className="input"
            type="number"
            value={current.port}
            onChange={(e) => set({ port: Number(e.target.value) || 0 })}
          />
        </Field>

        {lockedProtocol && (
          <Field label="MTU" hint={t(isAwg ? "srv.awgHint" : "srv.warpEndpointHint")}>
            <input
              className="input"
              type="number"
              value={current.mtu}
              onChange={(e) => set({ mtu: Number(e.target.value) || 0 })}
            />
          </Field>
        )}

        {isMasque && (
          <Field label={t("srv.masqueUserLabel")}>
            <input
              className="input mono"
              value={current.username}
              onChange={(e) => set({ username: e.target.value })}
              placeholder="client@example.com"
            />
          </Field>
        )}

        {needsUuid && (
          <Field label="UUID">
            <input
              className="input mono"
              value={current.uuid}
              onChange={(e) => set({ uuid: e.target.value })}
            />
          </Field>
        )}
        {needsPassword && (
          <Field label={t("srv.passwordLabel")}>
            <input
              className="input mono"
              value={current.password}
              onChange={(e) => set({ password: e.target.value })}
            />
          </Field>
        )}
        {current.protocol === "shadowsocks" && (
          <Field label={t("srv.encryptionLabel")}>
            <input
              className="input"
              value={current.method}
              onChange={(e) => set({ method: e.target.value })}
            />
          </Field>
        )}

        {hasTransport && (
          <>
            <Field label={t("srv.transportLabel")}>
              <select
                className="select"
                value={current.network}
                onChange={(e) => set({ network: e.target.value as Network })}
              >
                {NETWORKS.map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("srv.channelEncryptionLabel")}>
              <select
                className="select"
                value={current.security}
                onChange={(e) => set({ security: e.target.value as Security })}
              >
                {SECURITIES.map((s) => (
                  <option key={s} value={s}>
                    {s === "none" ? t("srv.noTls") : s.toUpperCase()}
                  </option>
                ))}
              </select>
            </Field>
          </>
        )}

        {current.network !== "tcp" && hasTransport && (
          <>
            <Field label="Path">
              <input
                className="input mono"
                value={current.path}
                onChange={(e) => set({ path: e.target.value })}
                placeholder="/"
              />
            </Field>
            <Field label="Host">
              <input
                className="input"
                value={current.host}
                onChange={(e) => set({ host: e.target.value })}
              />
            </Field>
          </>
        )}
        {current.network === "grpc" && (
          <Field label="serviceName">
            <input
              className="input mono"
              value={current.serviceName}
              onChange={(e) => set({ serviceName: e.target.value })}
            />
          </Field>
        )}

        {hasTransport && current.security !== "none" && (
          <>
            <Field label="SNI">
              <input
                className="input"
                value={current.sni}
                onChange={(e) => set({ sni: e.target.value })}
              />
            </Field>
            <Field label={t("srv.tlsFingerprintLabel")}>
              <input
                className="input"
                value={current.fingerprint}
                onChange={(e) => set({ fingerprint: e.target.value })}
                placeholder="chrome"
              />
            </Field>
          </>
        )}

        {hasTransport && current.security === "reality" && (
          <>
            <Field label="Public key (pbk)">
              <input
                className="input mono"
                value={current.publicKey}
                onChange={(e) => set({ publicKey: e.target.value })}
              />
            </Field>
            <Field label="Short id (sid)">
              <input
                className="input mono"
                value={current.shortId}
                onChange={(e) => set({ shortId: e.target.value })}
              />
            </Field>
          </>
        )}

        {current.protocol === "vless" && current.security !== "none" && (
          <Field label="Flow" hint={t("srv.flowHint")}>
            <input
              className="input mono"
              value={current.flow}
              onChange={(e) => set({ flow: e.target.value })}
            />
          </Field>
        )}

        {isMasque && (
          <>
            <Field label="SNI">
              <input
                className="input"
                value={current.sni}
                onChange={(e) => set({ sni: e.target.value })}
                placeholder={current.address || "example.com"}
              />
            </Field>
            <Field label={t("srv.masqueHttpLabel")} hint={t("srv.masqueHint")}>
              <select
                className="select"
                value={masqueHttp2(current.alpn) ? "h2" : "h3"}
                onChange={(e) => set({ alpn: [e.target.value] })}
              >
                <option value="h3">HTTP/3 (QUIC)</option>
                <option value="h2">HTTP/2 (TCP)</option>
              </select>
            </Field>
            <Field label="Path">
              <input
                className="input mono"
                value={current.path}
                onChange={(e) => set({ path: e.target.value })}
                placeholder="/.well-known/masque/ip/{target}/{ipproto}/"
              />
            </Field>
          </>
        )}
      </div>

      {hasTransport && current.security === "tls" && (
        <ToggleRow
          label={t("srv.skipCertLabel")}
          desc={t("srv.skipCertDesc")}
          checked={current.allowInsecure}
          onChange={(allowInsecure) => set({ allowInsecure })}
        />
      )}
      {/* Share links carry no mux flag, so a brand-new node is created through
          the parser without it; it becomes editable once the node exists. */}
      {!isNew && hasTransport && !current.flow.includes("vision") && (
        <ToggleRow
          label={t("srv.muxLabel")}
          desc={t("srv.muxDesc")}
          checked={current.mux}
          onChange={(mux) => set({ mux })}
        />
      )}
    </Modal>
  );
}

/** base64 that survives non-ASCII input — `btoa` alone throws on Cyrillic. */
function b64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Serialise a hand-edited node back into a share link for the Rust parser. */
function buildLink(node: ServerNode): string {
  // MASQUE has no share link at all; a one-server Xray config, the form a
  // JSON subscription brings it in, goes through the same parser instead.
  if (node.protocol === "masque") {
    return JSON.stringify({
      remarks: node.name,
      outbounds: [
        {
          protocol: "masque",
          settings: { address: node.address, port: node.port },
          streamSettings: {
            network: "masque",
            security: "tls",
            tlsSettings: {
              serverName: node.sni || undefined,
              alpn: node.alpn.length > 0 ? node.alpn : undefined,
              fingerprint: node.fingerprint || undefined,
            },
            masqueSettings: {
              path: node.path || undefined,
              user: node.username || undefined,
              pass: node.password || undefined,
            },
          },
        },
      ],
    });
  }

  // VMess has no query-string form: it is a base64-encoded JSON document.
  // VMess has no query-string form: it is a base64-encoded JSON document.
  if (node.protocol === "vmess") {
    return `vmess://${b64(
      JSON.stringify({
        v: "2",
        ps: node.name,
        add: node.address,
        port: String(node.port),
        id: node.uuid,
        aid: String(node.alterId),
        scy: node.vmessSecurity || "auto",
        net: node.network,
        type: "none",
        host: node.host,
        path: node.path,
        tls: node.security === "none" ? "" : "tls",
        sni: node.sni,
        fp: node.fingerprint,
        alpn: node.alpn.join(","),
      }),
    )}`;
  }

  const query = new URLSearchParams();
  query.set("type", node.network);
  query.set("security", node.security);
  if (node.path) query.set("path", node.path);
  if (node.host) query.set("host", node.host);
  if (node.serviceName) query.set("serviceName", node.serviceName);
  if (node.sni) query.set("sni", node.sni);
  if (node.fingerprint) query.set("fp", node.fingerprint);
  if (node.publicKey) query.set("pbk", node.publicKey);
  if (node.shortId) query.set("sid", node.shortId);
  if (node.flow) query.set("flow", node.flow);
  if (node.allowInsecure) query.set("allowInsecure", "1");

  // Bracket bare IPv6 so the host/port split stays unambiguous.
  const host = node.address.includes(":") ? `[${node.address}]` : node.address;

  let credential: string;
  if (node.protocol === "shadowsocks") {
    credential = b64(`${node.method}:${node.password}`);
  } else if (node.protocol === "tuic") {
    // TUIC carries both parts in the userinfo, separated by a colon.
    credential = `${encodeURIComponent(node.uuid)}:${encodeURIComponent(node.password)}`;
  } else {
    credential = encodeURIComponent(node.uuid || node.password);
  }

  const scheme = node.protocol === "shadowsocks" ? "ss" : node.protocol;

  return `${scheme}://${credential}@${host}:${node.port}?${query.toString()}#${encodeURIComponent(node.name)}`;
}
