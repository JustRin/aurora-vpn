/**
 * The balancer strategies as list entries, next to the servers — the way
 * Hiddify lists its «Auto» group: a separate item you pick, not a toggle
 * buried in settings. One icon per strategy tells it apart from a server at
 * a glance; the same table feeds the hero picker and the Servers page.
 */

import { LifeBuoy, type LucideIcon, Repeat, Zap } from "lucide-react";

import type { MsgKey } from "./i18n";
import type { Balancer, ServerNode, Status } from "./types";
import { shownServerId } from "./types";

export type Strategy = Exclude<Balancer, "manual">;

export interface BalancerEntry {
  id: Strategy;
  icon: LucideIcon;
  label: MsgKey;
  /** What the strategy will do — shown while it is not the one in charge. */
  meta: MsgKey;
}

export const BALANCERS: readonly BalancerEntry[] = [
  { id: "failover", icon: LifeBuoy, label: "set.balancerFailover", meta: "pick.failoverMeta" },
  { id: "fastest", icon: Zap, label: "set.balancerFastest", meta: "pick.fastestMeta" },
  { id: "rotate", icon: Repeat, label: "set.balancerRotate", meta: "pick.rotateMeta" },
];

export function balancerEntry(balancer: Balancer | undefined): BalancerEntry | undefined {
  return BALANCERS.find((entry) => entry.id === balancer);
}

/** Failover moved traffic off the user's own pick: it stopped answering. */
export function onBackup(balancer: Balancer | undefined, status: Status): boolean {
  return (
    balancer === "failover" &&
    status.state === "connected" &&
    !!status.routedId &&
    status.routedId !== status.activeId
  );
}

type Translate = (key: MsgKey, vars?: Record<string, string | number>) => string;

/**
 * The line under a strategy's name: while it is in charge and connected,
 * which server it is using right now; otherwise what it would do, and for
 * failover which server it would guard.
 */
export function balancerMeta(
  t: Translate,
  entry: BalancerEntry,
  balancer: Balancer | undefined,
  status: Status,
  nodes: ServerNode[],
): string {
  const nameOf = (id: string) => nodes.find((n) => n.id === id)?.name ?? "";
  if (balancer === entry.id && status.state === "connected") {
    const now = t("pick.now", { name: nameOf(shownServerId(status)) });
    return onBackup(balancer, status) ? `${now} · ${t("pick.primaryDown")}` : now;
  }
  if (entry.id === "failover") {
    return t("pick.primary", { name: nameOf(status.activeId) || "—" });
  }
  return t(entry.meta);
}
