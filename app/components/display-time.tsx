"use client";

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Action, getTimeDisplayString } from "@/lib/utils";
import { useEffect, useState } from "react";

type Props = {
  time: string;
  action?: Action;
  className?: string;
  serverNow?: string;
};

export function DisplayTimeCell({
  time,
  action = Action.Created,
  className,
  serverNow,
}: Props) {
  const [isMounted, setIsMounted] = useState(false);
  const [displayString, setDisplayString] = useState<string>();

  useEffect(() => {
    setIsMounted(true);
    setDisplayString(getTimeDisplayString(time, action, serverNow));
  }, [time, action, serverNow]);

  if (!isMounted) {
    return <span className="animate-pulse">...</span>;
  }

  if (!displayString) {
    return <span>Invalid date</span>;
  }

  const isTooltip =
    displayString.includes("ago") || displayString === "Just now";

  return isTooltip ? (
    withTimestampTooltip(
      displayString,
      getTimeDisplayString(time, action, serverNow),
    )
  ) : (
    <span className={className}>{displayString}</span>
  );
}

function withTimestampTooltip(display: string, timeString: string | undefined) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild={true}>
          <span className="inline-block">{display}</span>
        </TooltipTrigger>
        <TooltipContent>
          <span>{timeString}</span>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
