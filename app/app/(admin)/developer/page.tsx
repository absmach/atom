import { ExternalLink } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function DeveloperPage() {
  return (
    <div className="grid gap-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Developer tools
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Advanced GraphQL tooling lives here, away from task-first
          administrator workflows.
        </p>
      </div>
      <Alert>
        <AlertTitle>GraphQL console is backend-served</AlertTitle>
        <AlertDescription>
          Enable `ATOM_GRAPHQL_CONSOLE_ENABLED=true` on Atom and open
          `/graphql/console` on the backend host.
        </AlertDescription>
      </Alert>
      <Card>
        <CardHeader>
          <CardTitle>Atom GraphQL Console</CardTitle>
          <CardDescription>
            Existing advanced API builder, operation explorer, and reusable
            GraphQL recipe surface.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild>
            <a
              href="http://localhost:8080/graphql/console"
              target="_blank"
              rel="noreferrer"
            >
              Open console
              <ExternalLink />
            </a>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
