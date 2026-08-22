import { useEffect, useLayoutEffect, useRef, useState } from "react";

export type Pill = { x: number; y: number; w: number; h: number };

/** Geometry of the selected child inside a group, for the one backdrop that
 * slides between them. The children carry only their text colour, so picking
 * another one moves a single element instead of repainting two at once.
 *
 * The host must be an `offsetParent` (`position: relative`): the numbers are
 * offsets within it, not viewport coordinates.
 *
 * `key` is whatever identifies the selection — the measurement re-runs when it
 * changes, because `selector` then matches a different element. The first
 * placement lands without a transition: on open the selection is already home,
 * it does not fly in from the corner. */
export function useSlidingPill<T extends HTMLElement>(selector: string, key: unknown) {
  const hostRef = useRef<T>(null);
  const [pill, setPill] = useState<Pill | null>(null);
  const [placed, setPlaced] = useState(false);

  useLayoutEffect(() => {
    const host = hostRef.current;
    const el = host?.querySelector<HTMLElement>(selector);
    if (!host || !el) return;
    const measure = () => {
      const next = {
        x: el.offsetLeft,
        y: el.offsetTop,
        w: el.offsetWidth,
        h: el.offsetHeight,
      };
      // Identical numbers must not re-render: the observer below would
      // otherwise see its own write and loop.
      setPill((prev) =>
        prev &&
        prev.x === next.x &&
        prev.y === next.y &&
        prev.w === next.w &&
        prev.h === next.h
          ? prev
          : next,
      );
    };
    measure();
    // The children move under us on a window resize, across the phone
    // breakpoint, and when a translation changes how wide a label sits.
    const ro = new ResizeObserver(measure);
    ro.observe(host);
    ro.observe(el);
    return () => ro.disconnect();
  }, [selector, key]);

  useEffect(() => {
    if (!pill || placed) return;
    // One frame parked at the starting position, then transitions may run.
    const frame = requestAnimationFrame(() => setPlaced(true));
    return () => cancelAnimationFrame(frame);
  }, [pill, placed]);

  return { hostRef, pill, placed };
}
