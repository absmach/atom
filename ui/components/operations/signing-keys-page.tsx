"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, KeyRound, RotateCw } from "lucide-react";
import { toast } from "sonner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { graphqlClient } from "@/lib/graphql/client";

type SigningKey = {
  kid: string;
  status: string;
  algorithm: string;
  createdAt: string;
  storageMode: "encrypted" | "plaintext";
  keyEncryptionKeyId: string | null;
};

type SigningKeysResponse = {
  signingKeys: SigningKey[];
};

const SIGNING_KEYS_QUERY = `
  query SigningKeys {
    signingKeys {
      kid
      status
      algorithm
      createdAt
      storageMode
      keyEncryptionKeyId
    }
  }
`;

const ROTATE_SIGNING_KEYS_MUTATION = `
  mutation RotateSigningKeys {
    rotateSigningKeys
  }
`;

export function SigningKeysPage() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["operations", "signing-keys"],
    queryFn: ({ signal }) =>
      graphqlClient<SigningKeysResponse>({
        query: SIGNING_KEYS_QUERY,
        signal,
      }),
  });

  const rotate = useMutation({
    mutationFn: () =>
      graphqlClient<{ rotateSigningKeys: boolean }>({
        query: ROTATE_SIGNING_KEYS_MUTATION,
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: ["operations", "signing-keys"],
      });
      await queryClient.invalidateQueries({
        queryKey: ["operations", "system-status"],
      });
      toast.success("Signing keys rotated");
    },
    onError: (error) => toast.error(error.message),
  });

  if (query.isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent className="grid gap-3">
          {["row-1", "row-2", "row-3"].map((row) => (
            <Skeleton className="h-10 w-full" key={row} />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (query.error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle />
        <AlertTitle>Signing keys unavailable</AlertTitle>
        <AlertDescription>{query.error.message}</AlertDescription>
      </Alert>
    );
  }

  const keys = query.data?.signingKeys ?? [];
  const hasPlaintext = keys.some((key) => key.storageMode === "plaintext");

  return (
    <div className="grid gap-4">
      {hasPlaintext ? (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Plaintext signing keys detected</AlertTitle>
          <AlertDescription>
            Configure `ATOM_KEY_ENCRYPTION_KEY` and restart Atom to encrypt
            legacy rows in place.
          </AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="size-4" />
              Signing Keys
            </CardTitle>
            <CardDescription>
              {keys.length} {keys.length === 1 ? "key" : "keys"}
            </CardDescription>
          </div>
          <RotateDialog
            disabled={rotate.isPending}
            onConfirm={() => rotate.mutate()}
          />
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>KID</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Storage</TableHead>
                  <TableHead>Key ID</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.length > 0 ? (
                  keys.map((key) => (
                    <TableRow key={key.kid}>
                      <TableCell className="font-mono text-xs">
                        {key.kid}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{key.status}</Badge>
                      </TableCell>
                      <TableCell>{key.algorithm}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            key.storageMode === "plaintext"
                              ? "destructive"
                              : "outline"
                          }
                        >
                          {key.storageMode}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {key.keyEncryptionKeyId ?? "—"}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(key.createdAt).toLocaleString()}
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell
                      className="h-24 text-center text-sm text-muted-foreground"
                      colSpan={6}
                    >
                      No signing keys found.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function RotateDialog({
  disabled,
  onConfirm,
}: {
  disabled: boolean;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button disabled={disabled} size="sm" variant="outline">
          <RotateCw className="size-4" />
          Rotate
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Rotate signing keys?</AlertDialogTitle>
          <AlertDialogDescription>
            The current primary key becomes standby and a new encrypted primary
            signing key is created.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Rotate</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
