import { type Tag, TagInput } from "emblor";
import { type Dispatch, type SetStateAction, useState } from "react";
import {
  FormControl,
  FormDescription,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { cn } from "@/lib/utils";

export function TagsFormInput({
  newTags,
  setTags,
  field,
  label = "Tags",
  placeholder = "Enter tags",
  allowDuplicates,
  className,
}: {
  newTags: Tag[];
  setTags: Dispatch<SetStateAction<Tag[]>>;
  // biome-ignore lint: field can be of type any
  field: any;
  label?: string;
  placeholder?: string;
  allowDuplicates?: boolean;
  className?: string;
}) {
  const [activeTagIndex, setActiveTagIndex] = useState<number | null>(null);

  return (
    <FormItem className="flex flex-col items-start">
      <FormLabel className="text-left">{label}</FormLabel>
      <FormControl className="w-full">
        <TagInput
          {...field}
          placeholder={placeholder}
          tags={newTags}
          setTags={(updatedTags) => {
            setTags(updatedTags);
          }}
          showCounter={true}
          name="tags"
          shape="rounded"
          truncate={45}
          className="pl-2"
          styleClasses={{
            tagList: {
              container: cn(className, "p-2"),
            },
          }}
          activeTagIndex={activeTagIndex}
          setActiveTagIndex={setActiveTagIndex}
          allowDuplicates={allowDuplicates}
          inlineTags={false}
          inputFieldPosition="top"
        />
      </FormControl>
      <FormDescription className="text-xs text-muted-foreground">
        Press <span className="font-extrabold">Enter</span> to add multiple{" "}
        {label.toLowerCase()}.
      </FormDescription>
      <FormMessage />
    </FormItem>
  );
}
