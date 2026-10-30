import { useCallback, useEffect, useRef, useState } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";

/**
 * Drag-to-reorder for a vertical list of rows.
 *
 * Pointer events rather than HTML5 drag-and-drop: the latter never fires on a
 * touchscreen, and the app ships on Android. The drag starts from a grip rather
 * than from the row itself, so a press anywhere else still scrolls the list and
 * still reaches the buttons a row carries.
 *
 * The list is reordered live while the pointer moves — the row the user is
 * holding walks through the others — and only what they end up with is sent to
 * the backend, once, on release.
 *
 * The rows may differ in height: a server list's sections do, by as much as the
 * servers open under them.
 */
export interface Reorder {
  /** Ids in the order to render right now: the live one while dragging. */
  order: string[] | null;
  /** The row being held, for styling. */
  dragging: string | null;
  /** Spread onto the grip of each row. */
  gripProps: (id: string) => GripProps;
}

export interface GripProps {
  onPointerDown: (e: ReactPointerEvent) => void;
}

/** Distance from the viewport edge where the list starts scrolling itself. */
const EDGE = 70;
const EDGE_SPEED = 14;
const EDGE_TICK = 16;

/** The nearest ancestor that actually scrolls, or the document. */
function scrollParent(from: HTMLElement | null): HTMLElement {
  let node = from?.parentElement ?? null;
  while (node) {
    const style = getComputedStyle(node);
    const scrolls = /auto|scroll|overlay/.test(style.overflowY);
    if (scrolls && node.scrollHeight > node.clientHeight) return node;
    node = node.parentElement;
  }
  return document.scrollingElement as HTMLElement;
}

export function useReorder(
  ids: string[],
  commit: (order: string[]) => void | Promise<void>,
): Reorder {
  const [order, setOrder] = useState<string[] | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);

  // Read from pointer handlers and the auto-scroll loop, which must not be torn
  // down and rebuilt on every move.
  const latest = useRef<{ order: string[] | null; ids: string[] }>({ order: null, ids });
  latest.current.ids = ids;
  latest.current.order = order;

  const edge = useRef(0);
  /** Handle of the auto-scroll timer, 0 when it is not running. */
  const frame = useRef(0);
  /** Снимает слушателей текущего перетаскивания. */
  const unlisten = useRef<(() => void) | null>(null);

  const stopScrolling = useCallback(() => {
    if (frame.current) clearInterval(frame.current);
    frame.current = 0;
    edge.current = 0;
  }, []);

  useEffect(
    () => () => {
      unlisten.current?.();
      stopScrolling();
    },
    [stopScrolling],
  );

  const gripProps = useCallback(
    (id: string) => ({
      onPointerDown(e: ReactPointerEvent) {
        // Стрелка мыши и палец на экране: тянуть можно только основной кнопкой.
        if (e.button !== 0) return;
        e.preventDefault();
        e.stopPropagation();
        const grip = e.currentTarget as HTMLElement;
        const pointer = e.pointerId;
        // Капчур — удобство, а не условие: перестановка переносит удерживаемую
        // строку в DOM, и браузер его снимает. Поэтому события слушает окно, а
        // не ручка: у строки разной высоты ручка ещё и уезжает из-под пальца.
        try {
          grip.setPointerCapture(pointer);
        } catch {
          /* указателя уже нет — тянем без захвата */
        }
        setDragging(id);
        setOrder(latest.current.ids.slice());

        const onMove = (move: PointerEvent) => {
          if (move.pointerId !== pointer) return;
          const current = latest.current.order;
          if (!current) return;
          move.preventDefault();

          // Только свои: внутри раздела лежат строки вложенного списка.
          const rows = Array.from(
            (grip.closest("[data-reorder-list]") ?? document).querySelectorAll<HTMLElement>(
              "[data-reorder-id]",
            ),
          ).filter((row) => current.includes(row.dataset.reorderId ?? ""));
          const under = rows.find((row) => {
            const box = row.getBoundingClientRect();
            return move.clientY >= box.top && move.clientY <= box.bottom;
          });
          const held = rows.find((row) => row.dataset.reorderId === id);

          const overId = under?.dataset.reorderId;
          if (under && held && overId && overId !== id) {
            // Меняться, только если после обмена палец окажется на своей же
            // строке. Иначе короткая, встав за высокой, снова оказалась бы под
            // ней — и они менялись бы местами на каждое движение.
            const box = under.getBoundingClientRect();
            const height = held.getBoundingClientRect().height;
            const reached =
              current.indexOf(overId) > current.indexOf(id)
                ? move.clientY >= box.bottom - height
                : move.clientY <= box.top + height;
            if (reached) {
              setOrder((now) => {
                if (!now) return now;
                const from = now.indexOf(id);
                const to = now.indexOf(overId);
                if (from < 0 || to < 0 || from === to) return now;
                const next = now.slice();
                next.splice(to, 0, ...next.splice(from, 1));
                return next;
              });
            }
          }

          // Дотянуть до конца списка из полусотни серверов, не отпуская: иначе
          // тащить можно только до края экрана. Прокрутку двигает таймер, а не
          // requestAnimationFrame: тот замирает всюду, где окно не рисуется, и
          // прокрутка тогда молча не работала бы.
          const top = move.clientY < EDGE;
          const bottom = move.clientY > window.innerHeight - EDGE;
          edge.current = top ? -EDGE_SPEED : bottom ? EDGE_SPEED : 0;
          if (edge.current !== 0 && !frame.current) {
            const scroller = scrollParent(grip);
            frame.current = window.setInterval(() => {
              if (edge.current === 0) {
                stopScrolling();
                return;
              }
              scroller.scrollBy(0, edge.current);
            }, EDGE_TICK);
          }
        };

        const onUp = (up: PointerEvent) => {
          if (up.pointerId !== pointer) return;
          const finished = latest.current.order;
          end();
          // Отпустили там же, откуда взяли — записывать нечего.
          if (finished && finished.join() !== latest.current.ids.join()) {
            // Без захвата мышь отпускают над другим элементом, и щелчок достаётся
            // их общему предку — например, карточке, что сворачивает раздел.
            const swallow = (click: MouseEvent) => click.stopPropagation();
            window.addEventListener("click", swallow, { capture: true, once: true });
            setTimeout(() => window.removeEventListener("click", swallow, true), 0);
            void commit(finished);
          }
        };

        const onCancel = (cancel: PointerEvent) => {
          if (cancel.pointerId === pointer) end();
        };

        function end() {
          unlisten.current?.();
          stopScrolling();
          setDragging(null);
          setOrder(null);
        }

        unlisten.current?.();
        window.addEventListener("pointermove", onMove);
        window.addEventListener("pointerup", onUp);
        window.addEventListener("pointercancel", onCancel);
        unlisten.current = () => {
          window.removeEventListener("pointermove", onMove);
          window.removeEventListener("pointerup", onUp);
          window.removeEventListener("pointercancel", onCancel);
          unlisten.current = null;
        };
      },
    }),
    [commit, stopScrolling],
  );

  return { order, dragging, gripProps };
}

/** Rows in the order to render: the live one while dragging, else as given. */
export function applyOrder<T extends { id: string }>(rows: T[], order: string[] | null): T[] {
  if (!order) return rows;
  const byId = new Map(rows.map((row) => [row.id, row]));
  const sorted = order.map((id) => byId.get(id)).filter((row): row is T => row !== undefined);
  // Узел, появившийся пока тянули (обновилась подписка), не должен пропасть с
  // экрана до конца перетаскивания.
  for (const row of rows) if (!order.includes(row.id)) sorted.push(row);
  return sorted;
}
