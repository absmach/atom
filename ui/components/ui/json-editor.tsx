"use client";

import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";
import { EditorView, type ReactCodeMirrorProps } from "@uiw/react-codemirror";
import dynamic from "next/dynamic";
import { useTheme } from "next-themes";
import { cn } from "@/lib/utils";

const _CodeMirror = dynamic<ReactCodeMirrorProps>(
  () => import("@uiw/react-codemirror").then((m) => m.default),
  { ssr: false },
);

const VIEW_EXTENSIONS = [json(), EditorView.lineWrapping];
const EDIT_EXTENSIONS = [
  json(),
  linter(jsonParseLinter()),
  EditorView.lineWrapping,
];

type JsonEditorProps = {
  value: string;
  onChange?: (value: string) => void;
  className?: string;
};

export function JsonEditor({ value, onChange, className }: JsonEditorProps) {
  const { resolvedTheme } = useTheme();
  const isEdit = Boolean(onChange);

  return (
    <_CodeMirror
      value={value}
      onChange={onChange}
      theme={resolvedTheme === "dark" ? "dark" : "light"}
      editable={isEdit}
      readOnly={!isEdit}
      extensions={isEdit ? EDIT_EXTENSIONS : VIEW_EXTENSIONS}
      basicSetup={{
        foldGutter: true,
        lineNumbers: true,
        highlightActiveLine: false,
        highlightActiveLineGutter: false,
      }}
      className={cn(
        "max-w-full overflow-hidden rounded-md border bg-background text-xs",
        "[&_.cm-content]:max-w-full [&_.cm-gutters]:border-r [&_.cm-line]:break-words [&_.cm-scroller]:font-mono",
        "[&_.cm-editor]:min-h-36",
        className,
      )}
    />
  );
}
