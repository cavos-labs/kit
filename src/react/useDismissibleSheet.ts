import { useCallback, useEffect, useRef, useState } from "react";

/**
 * A bottom sheet you can throw away with your thumb.
 *
 * The sheet used to arrive on a fixed `@keyframes` slide and could only be
 * dismissed by tapping outside it. That is fine until someone tries to push it
 * down — which is the first thing a thumb does with a sheet, because every
 * sheet on the platform works that way — and nothing moves.
 *
 * What this adds, in the order it matters:
 *
 *   1. The sheet tracks the finger 1:1 from wherever it was grabbed. If touch
 *      and content do not move together the illusion is gone immediately, and
 *      no amount of easing afterwards recovers it.
 *   2. Release hands the finger's velocity straight to the spring, so there is
 *      no seam between dragging and animating.
 *   3. Where it lands is decided by projecting the momentum forward, not by
 *      where the finger happened to let go. A short flick from near the top
 *      should dismiss; a long slow drag most of the way down should not.
 *   4. It can be grabbed again mid-flight. The new drag starts from the live
 *      on-screen position, so a sheet caught while closing follows the finger
 *      back up instead of finishing its exit first.
 *
 * There is no animation library here on purpose. A spring is about fifteen
 * lines, and an SDK that ships a UI should not push a motion runtime into
 * every app that installs it.
 */

/** Where the sheet sits, in pixels below its resting position. */
type Offset = number;

export interface DismissibleSheet {
  /** Spread onto the sheet element. */
  handlers: {
    onPointerDown: (event: React.PointerEvent) => void;
    onPointerMove: (event: React.PointerEvent) => void;
    onPointerUp: (event: React.PointerEvent) => void;
    onPointerCancel: (event: React.PointerEvent) => void;
  };
  /** Live translation, in px. Apply as `translateY`. */
  offset: Offset;
  /**
   * How far gone the sheet is, 0 at rest and 1 when fully dismissed.
   *
   * The scrim is driven from this rather than animated separately. A backdrop
   * that holds full strength while the sheet slides out from under it reads as
   * two unrelated layers, and the moment the sheet lands the backdrop pops —
   * which is the single clearest tell that a sheet is not the real thing.
   */
  progress: number;
  /** True while a finger is down, so the caller can suppress its own entry animation. */
  dragging: boolean;
  /**
   * Whether this element takes the gesture at all.
   *
   * The caller needs it for `touch-action`, which the browser reads once when
   * the touch starts and never again — so it cannot be flipped on mid-drag.
   * Leaving it at `pan-y` until a drag was detected meant the browser claimed
   * the first vertical move for scrolling, cancelled the pointer stream, and
   * the sheet stopped following the finger it had just started following.
   */
  /**
   * Tuck the sheet away and call back once it has gone.
   *
   * The same spring the gesture uses, so closing by tapping outside and closing
   * by throwing it look like the same object doing the same thing — which is
   * the point of a sheet having a physical position at all.
   */
  dismiss: (done: () => void) => void;
  draggable: boolean;
}

/** Damping ratio and response, in Apple's terms, for a drawer. */
const DAMPING = 0.8;
const RESPONSE = 0.3;

/** Movement before a drag is a drag and not a tap. */
const HYSTERESIS = 10;

/**
 * Deceleration constant for momentum projection — the same exponential-decay
 * form scrolling uses, not the physics-textbook v²/2a, which projects much too
 * far and makes every flick dismiss.
 */
const DECELERATION = 0.998;

/** Fraction of the sheet's height that, once projected past, commits the dismiss. */
const COMMIT_FRACTION = 0.4;

function project(velocity: number): number {
  return ((velocity / 1000) * DECELERATION) / (1 - DECELERATION);
}

/**
 * Resistance above the resting position.
 *
 * A sheet dragged upwards has nowhere to go, and stopping dead reads as frozen
 * rather than as a boundary. Following less and less says "there is nothing
 * more here" while staying alive under the finger.
 */
function rubberband(overshoot: number, dimension: number): number {
  const constant = 0.55;
  return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
}

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

export function useDismissibleSheet(
  enabled: boolean,
  open: boolean,
  onDismiss: () => void,
): DismissibleSheet {
  const [offset, setOffset] = useState<Offset>(0);
  const [dragging, setDragging] = useState(false);

  // Everything the gesture needs lives in a ref: it is read inside pointer
  // handlers and an rAF loop, neither of which should re-render to read it.
  const state = useRef({
    /** Explicit, because clientY is legitimately 0 when you grab at the very top. */
    active: false,
    grabbedAt: 0,
    startOffset: 0,
    /** The last few samples, for a velocity that reflects the release and not the whole drag. */
    samples: [] as { y: number; at: number }[],
    height: 0,
    offset: 0,
    frame: 0,
    committed: false,
  });

  const stop = useCallback(() => {
    if (state.current.frame) {
      cancelAnimationFrame(state.current.frame);
      state.current.frame = 0;
    }
  }, []);

  useEffect(() => stop, [stop]);

  // Reopening has to start from the top.
  //
  // Dismissing leaves the offset at the sheet's full height — that is what put
  // it off screen — and the modal only returns null when closed, so it stays
  // mounted and this hook keeps its state. Without this, a sheet dismissed by
  // dragging reopens still translated off the bottom: the backdrop appears and
  // the sheet does not.
  //
  // Only on the way open. Resetting on close would yank the sheet back into
  // view for a frame in the middle of the animation that is dismissing it.
  useEffect(() => {
    if (!open) return;
    stop();
    state.current.offset = 0;
    state.current.active = false;
    state.current.committed = false;
    setOffset(0);
    setDragging(false);
  }, [open, stop]);

  /**
   * Spring to `target`, starting at the current position and the given
   * velocity. Called on release, and on any interruption — always from the
   * value on screen, never from where the previous animation was headed,
   * because starting from the logical value is what produces a visible jump.
   */
  const springTo = useCallback(
    (target: number, velocity: number, done?: () => void) => {
      stop();
      if (prefersReducedMotion()) {
        state.current.offset = target;
        setOffset(target);
        done?.();
        return;
      }
      const omega = (2 * Math.PI) / RESPONSE;
      let position = state.current.offset;
      let speed = velocity;
      let previous = performance.now();

      const step = (now: number) => {
        // Clamp the timestep: a backgrounded tab hands back a gap large enough
        // to make the integration explode.
        const dt = Math.min((now - previous) / 1000, 1 / 30);
        previous = now;

        const acceleration =
          -omega * omega * (position - target) - 2 * DAMPING * omega * speed;
        speed += acceleration * dt;
        position += speed * dt;

        const settled = Math.abs(position - target) < 0.5 && Math.abs(speed) < 20;
        if (settled) {
          position = target;
          state.current.offset = position;
          setOffset(position);
          state.current.frame = 0;
          done?.();
          return;
        }
        state.current.offset = position;
        setOffset(position);
        state.current.frame = requestAnimationFrame(step);
      };
      state.current.frame = requestAnimationFrame(step);
    },
    [stop],
  );

  const onPointerDown = useCallback(
    (event: React.PointerEvent) => {
      if (!enabled || event.button !== 0) return;
      const element = event.currentTarget as HTMLElement;
      // Interrupting is the point: take over from wherever the sheet is now.
      stop();
      element.setPointerCapture(event.pointerId);
      const current = state.current;
      current.height = element.getBoundingClientRect().height || 1;
      current.active = true;
      current.grabbedAt = event.clientY;
      current.startOffset = current.offset;
      current.samples = [{ y: event.clientY, at: event.timeStamp }];
      current.committed = false;
    },
    [enabled, stop],
  );

  const onPointerMove = useCallback(
    (event: React.PointerEvent) => {
      const current = state.current;
      if (!enabled || !current.active) return;

      const travelled = event.clientY - current.grabbedAt;
      current.samples.push({ y: event.clientY, at: event.timeStamp });
      if (current.samples.length > 5) current.samples.shift();

      if (!current.committed) {
        if (Math.abs(travelled) < HYSTERESIS) return;
        current.committed = true;
        setDragging(true);
      }

      const raw = current.startOffset + travelled;
      // Downwards is free; upwards resists, because there is nothing up there.
      const next = raw >= 0 ? raw : -rubberband(-raw, current.height);
      current.offset = next;
      setOffset(next);
    },
    [enabled],
  );

  const release = useCallback(
    (event: React.PointerEvent) => {
      const current = state.current;
      if (!enabled || !current.active) return;
      const element = event.currentTarget as HTMLElement;
      if (element.hasPointerCapture?.(event.pointerId)) {
        element.releasePointerCapture(event.pointerId);
      }
      const wasDragging = current.committed;
      current.active = false;
      current.committed = false;
      setDragging(false);
      if (!wasDragging) return; // a tap, not a drag — leave it to the click handler

      // Velocity from the last samples only. Averaging the whole gesture would
      // report a slow drag as slow even when it ended in a flick.
      const samples = current.samples;
      const first = samples[0];
      const last = samples[samples.length - 1];
      const elapsed = last && first ? last.at - first.at : 0;
      const velocity = elapsed > 0 ? ((last.y - first.y) / elapsed) * 1000 : 0;

      // Where the throw would come to rest, not where the finger stopped.
      const projected = current.offset + project(velocity);
      const dismissing = projected > current.height * COMMIT_FRACTION;

      if (dismissing) {
        springTo(current.height, velocity, onDismiss);
      } else {
        springTo(0, velocity);
      }
    },
    [enabled, onDismiss, springTo],
  );

  const dismiss = useCallback(
    (done: () => void) => {
      // From rest, so there is no velocity to inherit; a throw goes through
      // `release` instead and brings its own.
      springTo(state.current.height || window.innerHeight, 0, done);
    },
    [springTo],
  );

  return {
    handlers: {
      onPointerDown,
      onPointerMove,
      onPointerUp: release,
      onPointerCancel: release,
    },
    offset,
    progress: Math.min(
      Math.max(offset / (state.current.height || (typeof window === "undefined" ? 1 : window.innerHeight)), 0),
      1,
    ),
    dragging,
    dismiss,
    draggable: enabled,
  };
}
