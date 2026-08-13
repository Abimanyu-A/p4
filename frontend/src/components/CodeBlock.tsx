interface CodeBlockProps {
  code: string;
}

export function CodeBlock({ code }: CodeBlockProps) {
  const lines = code.split("\n");
  return (
    <pre
      className="font-mono surface m-0 overflow-x-auto rounded-md p-3 text-[0.76rem] leading-relaxed"
      style={{ background: "var(--page)" }}
    >
      {lines.map((line, i) => {
        const flagged = line.startsWith(">>");
        return (
          <div
            key={i}
            className="px-1.5"
            style={
              flagged
                ? { background: "color-mix(in srgb, var(--status-critical) 12%, transparent)", borderRadius: 3 }
                : undefined
            }
          >
            {line}
          </div>
        );
      })}
    </pre>
  );
}
