import { type CSSProperties, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

type ActiveHelp = { element: HTMLElement; text: string };
type HelpPosition = {
  left: number;
  top: number;
  placement: "above" | "below";
  arrowLeft: number;
};

function helpTarget(target: EventTarget | null): HTMLElement | null {
  return target instanceof Element
    ? target.closest<HTMLElement>(".hover-help-title[data-help]")
    : null;
}

export function HoverHelpOverlay() {
  const [active, setActive] = useState<ActiveHelp | null>(null);
  const [position, setPosition] = useState<HelpPosition | null>(null);
  const overlayRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const show = (element: HTMLElement | null) => {
      if (!element) return;
      const text = element.dataset.help?.trim();
      if (!text) return;
      setActive({ element, text });
    };

    const hide = (element: HTMLElement | null) => {
      if (!element) return;
      setActive((current) => current?.element === element ? null : current);
    };

    const onPointerOver = (event: PointerEvent) => {
      const target = helpTarget(event.target);
      if (!target || helpTarget(event.relatedTarget) === target) return;
      show(target);
    };
    const onPointerOut = (event: PointerEvent) => {
      const target = helpTarget(event.target);
      if (!target || helpTarget(event.relatedTarget) === target) return;
      hide(target);
    };
    const onFocusIn = (event: FocusEvent) => show(helpTarget(event.target));
    const onFocusOut = (event: FocusEvent) => {
      const target = helpTarget(event.target);
      if (!target || helpTarget(event.relatedTarget) === target) return;
      hide(target);
    };

    document.addEventListener("pointerover", onPointerOver);
    document.addEventListener("pointerout", onPointerOut);
    document.addEventListener("focusin", onFocusIn);
    document.addEventListener("focusout", onFocusOut);
    return () => {
      document.removeEventListener("pointerover", onPointerOver);
      document.removeEventListener("pointerout", onPointerOut);
      document.removeEventListener("focusin", onFocusIn);
      document.removeEventListener("focusout", onFocusOut);
    };
  }, []);

  useLayoutEffect(() => {
    if (!active || !overlayRef.current) {
      setPosition(null);
      return;
    }

    const update = () => {
      if (!overlayRef.current || !active.element.isConnected) return;

      const anchor = active.element.getBoundingClientRect();
      const overlay = overlayRef.current.getBoundingClientRect();
      const viewportWidth = window.innerWidth;
      const viewportHeight = window.innerHeight;
      const edge = 8;

      // The tooltip body sits five pixels from the title. Its four-pixel pointer
      // occupies almost all of that distance, so the visible gap is ~1px.
      const bodyGap = 5;
      const arrowInset = 10;
      const nav = document.querySelector<HTMLElement>(".workspace-nav-strip");
      const navRect = nav?.getBoundingClientRect();
      const visibleChromeBottom = navRect && navRect.bottom > 0 && navRect.top < viewportHeight
        ? navRect.bottom + 2
        : edge;
      const topBoundary = Math.max(edge, visibleChromeBottom);

      const roomAbove = anchor.top - topBoundary;
      const roomBelow = viewportHeight - anchor.bottom - edge;
      const canFitAbove = roomAbove >= overlay.height + bodyGap;
      const canFitBelow = roomBelow >= overlay.height + bodyGap;
      const placement: "above" | "below" = canFitAbove || !canFitBelow ? "above" : "below";

      let top = placement === "above"
        ? anchor.top - overlay.height - bodyGap
        : anchor.bottom + bodyGap;
      top = Math.max(topBoundary, Math.min(top, viewportHeight - overlay.height - edge));

      const anchorCenter = anchor.left + anchor.width / 2;
      let left = anchorCenter - overlay.width / 2;
      left = Math.max(edge, Math.min(left, viewportWidth - overlay.width - edge));

      // Keep the pointer aimed at the title even when the tooltip has to shift
      // away from a viewport edge.
      const arrowLeft = Math.max(
        arrowInset,
        Math.min(anchorCenter - left, overlay.width - arrowInset),
      );

      setPosition({ left, top, placement, arrowLeft });
    };

    update();
    window.addEventListener("resize", update);
    window.addEventListener("scroll", update, true);
    return () => {
      window.removeEventListener("resize", update);
      window.removeEventListener("scroll", update, true);
    };
  }, [active]);

  if (!active || typeof document === "undefined") return null;

  return createPortal(
    <div
      ref={overlayRef}
      className="hover-help-overlay"
      data-placement={position?.placement || "above"}
      role="tooltip"
      style={position ? {
        left: position.left,
        top: position.top,
        "--hover-help-arrow-left": `${position.arrowLeft}px`,
      } as CSSProperties : undefined}
    >
      {active.text}
    </div>,
    document.body,
  );
}
