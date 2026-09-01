"use client";

import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Check, ChevronsUpDown, Loader2 } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/lib/utils";

export type ComboOption = {
  value: string;
  label: string;
  detail?: string;
};

export type ComboPage = {
  items: ComboOption[];
  /** Offset of the next page, or null when there are no more rows. */
  nextOffset: number | null;
};

type AsyncComboboxProps = {
  value: string;
  onChange: (value: string) => void;
  /** Fetches one page of options. `search` is empty in client mode. */
  fetchPage: (args: {
    search: string;
    offset: number;
    signal?: AbortSignal;
  }) => Promise<ComboPage>;
  /** Resolves the label of a preselected value not present in the loaded list. */
  fetchSelected?: (args: {
    value: string;
    signal?: AbortSignal;
  }) => Promise<ComboOption | null>;
  /** Notified with the resolved option for the current value (e.g. for previews). */
  onSelectedChange?: (option: ComboOption | null) => void;
  /** Stable base key for caching; search/offset are appended internally. */
  queryKey: readonly unknown[];
  /**
   * "server": the backend filters via `search` (default).
   * "client": the backend has no search arg, so loaded rows are filtered locally.
   */
  mode?: "server" | "client";
  placeholder?: string;
  searchPlaceholder?: string;
  emptyText?: string;
  disabled?: boolean;
  className?: string;
  id?: string;
};

function useDebounced<T>(value: T, delay = 250): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export function AsyncCombobox({
  value,
  onChange,
  fetchPage,
  fetchSelected,
  onSelectedChange,
  queryKey,
  mode = "server",
  placeholder = "Select…",
  searchPlaceholder = "Search…",
  emptyText = "No results.",
  disabled,
  className,
  id,
}: AsyncComboboxProps) {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const debouncedSearch = useDebounced(search);
  const serverSearch = mode === "server" ? debouncedSearch : "";
  // Remembers the option the user picked so its label survives cache eviction.
  const [picked, setPicked] = React.useState<ComboOption | null>(null);

  const query = useInfiniteQuery({
    // First page is prefetched on mount (no `enabled: open`) to avoid a loading
    // flash when the popover first opens.
    queryKey: [...queryKey, "options", serverSearch],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) =>
      fetchPage({ search: serverSearch, offset: pageParam, signal }),
    getNextPageParam: (last) => last.nextOffset,
    staleTime: 60_000,
  });

  const options = React.useMemo(
    () => query.data?.pages.flatMap((page) => page.items) ?? [],
    [query.data],
  );

  const selectedFromList = options.find((option) => option.value === value);
  const selectedQ = useQuery({
    queryKey: [...queryKey, "selected", value],
    enabled: Boolean(value) && !selectedFromList && Boolean(fetchSelected),
    queryFn: ({ signal }) => fetchSelected?.({ value, signal }) ?? null,
    staleTime: 60_000,
  });

  const selected =
    (picked?.value === value ? picked : null) ??
    selectedFromList ??
    selectedQ.data ??
    null;

  React.useEffect(() => {
    onSelectedChange?.(value ? selected : null);
  }, [value, selected, onSelectedChange]);

  function choose(option: ComboOption) {
    setPicked(option);
    onChange(option.value);
    setOpen(false);
  }

  function handleScroll(event: React.UIEvent<HTMLDivElement>) {
    const el = event.currentTarget;
    if (
      el.scrollHeight - el.scrollTop - el.clientHeight < 64 &&
      query.hasNextPage &&
      !query.isFetchingNextPage
    ) {
      query.fetchNextPage();
    }
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className={cn(
            "w-full justify-between font-normal",
            !value && "text-muted-foreground",
            className,
          )}
        >
          <span className="truncate">
            {value ? (selected?.label ?? value) : placeholder}
            {selected?.detail ? (
              <span className="ml-1.5 text-xs text-muted-foreground">
                {selected.detail}
              </span>
            ) : null}
          </span>
          <ChevronsUpDown className="size-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-[var(--radix-popover-trigger-width)] p-0"
        align="start"
      >
        <Command shouldFilter={mode === "client"}>
          <CommandInput
            placeholder={searchPlaceholder}
            value={search}
            onValueChange={setSearch}
          />
          <CommandList onScroll={handleScroll}>
            {query.isPending ? (
              <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" />
                Loading…
              </div>
            ) : query.isError ? (
              <div className="py-6 text-center text-sm text-destructive">
                Failed to load options.
              </div>
            ) : (
              <>
                <CommandEmpty>{emptyText}</CommandEmpty>
                <CommandGroup>
                  {options.map((option) => (
                    <CommandItem
                      key={option.value}
                      value={option.value}
                      keywords={[option.label, option.detail ?? ""]}
                      onSelect={() => choose(option)}
                    >
                      <Check
                        className={cn(
                          "size-4",
                          option.value === value ? "opacity-100" : "opacity-0",
                        )}
                      />
                      <span className="truncate">{option.label}</span>
                      {option.detail ? (
                        <span className="ml-1.5 text-xs text-muted-foreground">
                          {option.detail}
                        </span>
                      ) : null}
                    </CommandItem>
                  ))}
                </CommandGroup>
                {query.isFetchingNextPage ? (
                  <div className="flex items-center justify-center gap-2 py-3 text-xs text-muted-foreground">
                    <Loader2 className="size-3 animate-spin" />
                    Loading more…
                  </div>
                ) : null}
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
