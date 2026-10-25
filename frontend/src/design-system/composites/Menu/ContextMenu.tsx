import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import styles from "./ContextMenu.module.css";

const CONTEXT_MENU_OPEN_EVENT = "fttw-context-menu-open";
const CONTEXT_MENU_GAP = 8;
const CONTEXT_MENU_MARGIN = 8;

export type ContextMenuAnchor = { x: number; y: number };

export type ContextMenuItem = {
  id?: string;
  label: string;
  disabled?: boolean;
  danger?: boolean;
  title?: string;
  onClick: () => void | Promise<void>;
};

export function computeContextMenuPosition(
  anchor: ContextMenuAnchor,
  menuSize: { width: number; height: number },
  viewport: { width: number; height: number },
): ContextMenuAnchor {
  let x = anchor.x + CONTEXT_MENU_GAP;
  if (x + menuSize.width + CONTEXT_MENU_MARGIN > viewport.width) {
    x = anchor.x - CONTEXT_MENU_GAP - menuSize.width;
  }

  let y = anchor.y + CONTEXT_MENU_GAP;
  if (y + menuSize.height + CONTEXT_MENU_MARGIN > viewport.height) {
    y = anchor.y - CONTEXT_MENU_GAP - menuSize.height;
  }

  const maxX = Math.max(CONTEXT_MENU_MARGIN, viewport.width - menuSize.width - CONTEXT_MENU_MARGIN);
  const maxY = Math.max(CONTEXT_MENU_MARGIN, viewport.height - menuSize.height - CONTEXT_MENU_MARGIN);

  return {
    x: Math.min(Math.max(CONTEXT_MENU_MARGIN, x), maxX),
    y: Math.min(Math.max(CONTEXT_MENU_MARGIN, y), maxY),
  };
}

export function ContextMenuSurface({
  anchor,
  items,
  onClose,
  ariaLabel = "Context menu",
}: {
  anchor: ContextMenuAnchor | null;
  items: ContextMenuItem[];
  onClose: () => void;
  ariaLabel?: string;
}) {
  const [position, setPosition] = useState<ContextMenuAnchor>({ x: 0, y: 0 });
  const menuId = useRef(`context-${Math.random().toString(36).slice(2)}`);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  const layoutKey = items
    .map((item) => `${item.id || item.label}:${item.label}:${item.disabled ? "disabled" : "enabled"}`)
    .join("|");

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useLayoutEffect(() => {
    if (!anchor || !menuRef.current) return;
    const rect = menuRef.current.getBoundingClientRect();
    setPosition(computeContextMenuPosition(
      anchor,
      { width: rect.width, height: rect.height },
      { width: window.innerWidth, height: window.innerHeight },
    ));
  }, [anchor, layoutKey]);

  useEffect(() => {
    if (!anchor) return;

    const close = () => onCloseRef.current();
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCloseRef.current();
    };
    const closeOnAnotherMenu = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail;
      if (detail !== menuId.current) onCloseRef.current();
    };

    document.addEventListener("click", close);
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener(CONTEXT_MENU_OPEN_EVENT, closeOnAnotherMenu as EventListener);
    window.addEventListener("scroll", close, true);
    window.addEventListener("resize", close);

    document.dispatchEvent(new CustomEvent(CONTEXT_MENU_OPEN_EVENT, { detail: menuId.current }));

    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener(CONTEXT_MENU_OPEN_EVENT, closeOnAnotherMenu as EventListener);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", close);
    };
  }, [anchor]);

  if (!anchor) return null;

  return createPortal(
    <div
      ref={menuRef}
      className={styles.menu}
      style={{ left: position.x, top: position.y }}
      role="menu"
      aria-label={ariaLabel}
      onClick={(event) => event.stopPropagation()}
    >
      {items.map((item) => (
        <button
          key={item.id || item.label}
          type="button"
          role="menuitem"
          className={item.danger ? styles.danger : undefined}
          disabled={item.disabled}
          title={item.title}
          onClick={() => {
            if (item.disabled) return;
            onCloseRef.current();
            void item.onClick();
          }}
        >
          {item.label}
        </button>
      ))}
    </div>,
    document.body,
  );
}

export function ContextMenu({
  children,
  items,
}: {
  children: ReactNode;
  items: ContextMenuItem[];
}) {
  const [anchor, setAnchor] = useState<ContextMenuAnchor | null>(null);
  const close = useCallback(() => setAnchor(null), []);

  return (
    <div
      className={styles.target}
      onContextMenu={(event) => {
        event.preventDefault();
        event.stopPropagation();
        setAnchor({ x: event.clientX, y: event.clientY });
      }}
    >
      {children}
      <ContextMenuSurface anchor={anchor} items={items} onClose={close} />
    </div>
  );
}
