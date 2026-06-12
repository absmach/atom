"use client";
import { useDocsSearch } from "fumadocs-core/search/client";
import { SearchDialog } from "fumadocs-ui/components/dialog/search";
import type { SharedProps } from "fumadocs-ui/components/dialog/search";

export default function CustomSearchDialog(props: SharedProps) {
  const { search, setSearch, query } = useDocsSearch(
    {
      type: "static",
      from: `${process.env.NEXT_PUBLIC_BASE_PATH ?? ""}/api/search`,
    },
  );

  return (
    <SearchDialog
      search={search}
      onSearchChange={setSearch}
      isLoading={query.isLoading}
      results={query.data ?? "empty"}
      {...props}
    />
  );
}
