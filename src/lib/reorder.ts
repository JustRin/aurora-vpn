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
 */
export interface Reorder {
  /** Ids in the order to render right now: the live one while dragging. */
  order: string[] | null;
  /** The row being held, for styling. */
  dragging: string | null;
  /** Spread onto the grip of each row. */
  gripProps: (id: string) => {
    onPointerDown: (e: ReactPointerEvent) => void;
    onPointerMove: (e: ReactPointerEvent) => void;
    onPointerUp: (e: ReactPointerEvent) => void;
    onPointerCancel: (e: ReactPointerEvent) => void;
  };
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

  const stopScrolling = useCallback(() => {
    if (frame.current) clearInterval(frame.current);
    frame.current = 0;
    edge.current = 0;
  }, []);

  useEffect(() => stopScrolling, [stopScrolling]);

  const gripProps = useCallback(
    (id: string) => ({
      onPointerDown(e: ReactPointerEvent) {
        // Стрелка мыши и палец на экране: тянуть можно только основной кнопкой.
        if (e.button !== 0) return;
        e.preventDefault();
        e.stopPropagation();
        const grip = e.currentTarget as HTMLElement;
        // Капчур — удобство, а не условие: без него события всё равно доходят,
        // пока указатель над строкой. Ронять из-за него перетаскивание не за что.
        try {
          grip.setPointerCapture(e.pointerId);
        } catch {
          /* указателя уже нет — тянем без захвата */
        }
        setDragging(id);
        setOrder(latest.current.ids.slice());
      },

      onPointerMove(e: ReactPointerEvent) {
        if (!latest.current.order) return;
        e.preventDefault();

        const grip = e.currentTarget as HTMLElement;
        const rows = Array.from(
          (grip.closest("[data-reorder-list]") ?? document).querySelectorAll<HTMLElement>(
            "[data-reorder-id]",
          ),
        );
        const under = rows.find((row) => {
          const box = row.getBoundingClientRect();
          return e.clientY >= box.top && e.clientY <= box.bottom;
        });

        const overId = under?.dataset.reorderId;
        if (overId && overId !== id) {
          setOrder((current) => {
            if (!current) return current;
            const from = current.indexOf(id);
            const to = current.indexOf(overId);
            if (from < 0 || to < 0 || from === to) return current;
            const next = current.slice();
            next.splice(to, 0, ...next.splice(from, 1));
            return next;
          });
        }

        // Дотянуть до конца списка из полусотни серверов, не отпуская: иначе
        // тащить можно только до края экрана. Прокрутку двигает таймер, а не
        // requestAnimationFrame: тот замирает всюду, где окно не рисуется, и
        // прокрутка тогда молча не работала бы.
        const top = e.clientY < EDGE;
        const bottom = e.clientY > window.innerHeight - EDGE;
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
      },

      onPointerUp(e: ReactPointerEvent) {
        stopScrolling();
        const finished = latest.current.order;
        setDragging(null);
        setOrder(null);
        try {
          (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
        } catch {
          /* захвата и не было */
        }
        // Отпустили там же, откуда взяли — записывать нечего.
        if (finished && finished.join() !== latest.current.ids.join()) {
          void commit(finished);
        }
      },

      onPointerCancel() {
        stopScrolling();
        setDragging(null);
        setOrder(null);
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
