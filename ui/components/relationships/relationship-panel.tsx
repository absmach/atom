import { ArrowRight, Network, ShieldCheck, Users } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const relationships = [
  {
    icon: Users,
    source: "Principal Group Operators",
    relation: "contains",
    target: "user1",
    kind: "who",
  },
  {
    icon: ShieldCheck,
    source: "Plant operator role",
    relation: "allows",
    target: "read + publish",
    kind: "role",
  },
  {
    icon: Network,
    source: "Object Group Plant-A",
    relation: "contains",
    target: "channels",
    kind: "where",
  },
];

export function RelationshipPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Network className="size-4 text-primary" />
          Relationship trace
        </CardTitle>
        <CardDescription>
          Lightweight visual traces keep relationship reasoning usable before
          first-class graph APIs exist.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        {relationships.map((item) => (
          <div
            key={`${item.source}-${item.target}`}
            className="grid gap-2 rounded-lg border p-3 sm:grid-cols-[1fr_auto_1fr_auto] sm:items-center"
          >
            <div className="flex items-center gap-2">
              <item.icon className="size-4 text-muted-foreground" />
              <span className="font-medium">{item.source}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span>{item.relation}</span>
              <ArrowRight className="size-3" />
            </div>
            <div className="font-medium">{item.target}</div>
            <Badge variant="outline">{item.kind}</Badge>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
