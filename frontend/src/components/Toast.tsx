interface ToastProps {
  message: string | null;
}

export function Toast({ message }: ToastProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="surface-raised font-mono fixed bottom-6 left-1/2 z-50 -translate-x-1/2 rounded-md px-4 py-2.5 text-[0.8rem] shadow-lg transition-all duration-200"
      style={{
        opacity: message ? 1 : 0,
        pointerEvents: "none",
        transform: `translate(-50%, ${message ? "0" : "8px"})`,
      }}
    >
      {message}
    </div>
  );
}
