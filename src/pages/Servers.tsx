import {
  Copy,
  Gauge,
  Pencil,
  Plus,
  RefreshCw,
  Server as ServerIcon,
  Trash2,
} from "lucide-react";
import { useState } from "react";

import { SubscriptionCard } from "../components/SubscriptionCard";
import { Empty, Field, Modal, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { latencyTier, protocolLabel, transportLabel } from "../lib/format";
import { tNow, useT } from "../lib/i18n";
import type { ImportReport, Network, Protocol, Security, ServerNode } from "../lib/types";
import { useStore } from "../store";

const PROTOCOLS: Protocol[] = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "hysteria2",
  "tuic",
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
    subscriptionId: null,
    rawLink: "",
  };
}

export function Servers() {
  const t = useT();
  const nodes = useStore((s) => s.nodes);
  const subs = useStore((s) => s.subscriptions);
  const latency = useStore((s) => s.latency);
  const activeId = useStore((s) => s.status.activeId);
  const testing = useStore((s) => s.busy.latency);
  const selectServer = useStore((s) => s.selectServer);
  const refreshLatency = useStore((s) => s.refreshLatency);
  const reload = useStore((s) => s.reload);
  const toast = useStore((s) => s.toast);

  const [importOpen, setImportOpen] = useState(false);
  const [refreshingAll, setRefreshingAll] = useState(false);
  const [editing, setEditing] = useState<ServerNode | null>(null);

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
            className="btn primary"
            onClick={() => setImportOpen(true)}
          >
            <Plus size={15} />
            {t("srv.addBtn")}
          </button>
        </div>
      </div>

      {subs.length > 0 && (
        <>
          <div className="row between" style={{ marginBottom: 11 }}>
            <div className="section-title" style={{ margin: 0 }}>
              {t("srv.subscriptions")}
            </div>
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
          </div>

          <div className="grid-2" style={{ marginBottom: 8 }}>
            {subs.map((sub) => (
              <div key={sub.id} style={{ position: "relative" }}>
                <SubscriptionCard sub={sub} />
                <button
                  type="button"
                  className="btn ghost icon sm sub-delete"
                  title={t("srv.deleteSubTitle")}
                  onClick={async () => {
                    await api.deleteSubscription(sub.id);
                    await reload();
                  }}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="section-title">
        {t("srv.title")} {nodes.length > 0 && <span>({nodes.length})</span>}
      </div>

      {nodes.length === 0 ? (
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
      ) : (
        <div className="list">
          {nodes.map((node) => {
            const ms = latency[node.id];
            const tier = latencyTier(ms);
            return (
              <div
                key={node.id}
                className={`node${node.id === activeId ? " active" : ""}`}
                onDoubleClick={() => void selectServer(node.id)}
              >
                <button
                  type="button"
                  className="node-radio"
                  aria-label={t("srv.selectServer")}
                  onClick={() => void selectServer(node.id)}
                />
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="node-name truncate">{node.name}</div>
                  <div className="node-meta">
                    <span className="chip">{protocolLabel(node.protocol)}</span>
                    <span>{transportLabel(node.security, node.network)}</span>
                    <span>·</span>
                    <span className="truncate">
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
                    onClick={() => void copyLink(node)}
                  >
                    <Copy size={14} />
                  </button>
                  <button
                    type="button"
                    className="btn ghost icon"
                    title={t("srv.editTitle")}
                    onClick={() => setEditing(node)}
                  >
                    <Pencil size={14} />
                  </button>
                  <button
                    type="button"
                    className="btn ghost icon"
                    title={t("srv.deleteTitle")}
                    onClick={() => void remove(node)}
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

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
  const needsPassword = ["trojan", "shadowsocks", "hysteria2", "tuic"].includes(
    current.protocol,
  );
  const hasTransport = !["hysteria2", "tuic"].includes(current.protocol);

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
            onChange={(e) => set({ protocol: e.target.value as Protocol })}
          >
            {PROTOCOLS.map((p) => (
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

        {current.security !== "none" && (
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

        {current.security === "reality" && (
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
      </div>

      {current.security === "tls" && (
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
