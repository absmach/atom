import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import { DateTime, Duration } from "luxon";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export enum Action {
  Created = "created",
  Updated = "updated",
  Confirmed = "confirmed",
  Rejected = "rejected",
  LastUsed = "lastused",
  Expired = "expired",
  Resolved = "resolved",
  Acknowledged = "acknowledged",
  Assigned = "assigned",
}
export function getTimeDisplayString(
  time: string,
  action: Action = Action.Created,
  serverNow?: string,
): string {
  const now = serverNow ? DateTime.fromISO(serverNow) : DateTime.now();
  const dateTime = DateTime.fromISO(time);

  if (
    dateTime.toString() ===
    DateTime.fromISO("0001-01-01T00:00:00.000Z").toString()
  ) {
    switch (action) {
      case Action.Created:
        return "Not created yet";
      case Action.Updated:
        return "Not updated yet";
      case Action.Confirmed:
        return "Not confirmed yet";
      case Action.Rejected:
        return "Not rejected yet";
      case Action.LastUsed:
        return "Not used yet";
      case Action.Resolved:
        return "Not resolved yet";
      case Action.Acknowledged:
        return "Not acknowledged yet";
      case Action.Assigned:
        return "Not assigned yet";
      default:
        return "Invalid date";
    }
  }

  const timeString = dateTime.toLocaleString({
    weekday: "short",
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  if (action === Action.Expired) {
    const diff = dateTime.diff(now, ["hours", "minutes", "seconds"]);
    if (diff.toMillis() <= 0) {
      return `Expired at ${dateTime.toLocaleString(
        DateTime.DATETIME_FULL_WITH_SECONDS,
      )}`;
    }
    return `Expires in ${diff.hours}h ${diff.minutes}m ${diff.seconds.toFixed(
      0,
    )}s`;
  }

  const diff = now.diff(dateTime, ["hours", "minutes", "seconds"]);

  if (diff.hours === 0 && diff.minutes === 0 && diff.seconds <= 6) {
    return "Just now";
  }

  if (diff.hours < 1) {
    return `${diff.minutes}m ${diff.seconds.toFixed(0)}s ago`;
  }

  if (diff.hours < 24) {
    return `${diff.hours}h ${diff.minutes}m ago`;
  }

  return timeString;
}

export const formatReadableDuration = (duration: string): string => {
  if (!duration) {
    return "";
  }

  const match = duration.match(/(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?/i);
  if (!match) {
    return duration;
  }

  const [, d, h, m, s] = match;
  const dur = Duration.fromObject({
    days: Number(d || 0),
    hours: Number(h || 0),
    minutes: Number(m || 0),
    seconds: Number(s || 0),
  }).shiftTo("days", "hours", "minutes", "seconds");

  const parts: string[] = [];
  const add = (value: number, suffix: string) => {
    if (Math.floor(value) > 0) {
      parts.push(`${Math.floor(value)}${suffix}`);
    }
  };

  add(dur.days, "d");
  add(dur.hours, "h");
  add(dur.minutes, "m");
  add(dur.seconds, "s");

  return parts.length > 0 ? parts.join(" ") : duration;
};
