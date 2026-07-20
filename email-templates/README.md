These are Atom's built-in default email templates, baked into the container
image at `/app/email-templates`. Each template is a single `.tmpl` file: a
`Subject: ...` header line, an optional `Content-Type: ...` header line
(defaults to `text/plain` when omitted — set it to `text/html` for a
branded HTML email), a blank line, then the body — both header values and
the body are rendered with [minijinja](https://docs.rs/minijinja)
`{{ variable }}` syntax.

```
Subject: Verify your Atom account

Verify your Atom account by opening this link:

{{ verification_url }}
```

An HTML override looks like:

```
Subject: Verify your Atom account
Content-Type: text/html

<!doctype html>
<html>...<a href="{{ verification_url }}">Verify email</a>...</html>
```

| Template            | Variables         | Trigger                          |
| ------------------- | ----------------- | --------------------------------- |
| `verification.tmpl`   | `verification_url` | Signup and `/auth/email/resend`   |
| `password_reset.tmpl` | `reset_url`        | `/auth/password/reset` request    |
| `invitation.tmpl`     | `invitation_url`   | Tenant invitation created         |

## Overriding at runtime

To customize copy/branding without rebuilding the image, mount a directory
over the default one and point `ATOM_EMAIL_TEMPLATES_DIR` at it. Only the
files you actually want to override need to be present — anything missing
falls back to the built-in default shown here. For example, to override only
the verification email:

```
my-email-templates/
  verification.tmpl
```

```dotenv
# .env used by docker compose
ATOM_EMAIL_TEMPLATES_DIR=/email-templates
ATOM_EMAIL_TEMPLATES_HOST_DIR=./my-email-templates
```

`docker-compose.yml` mounts `${ATOM_EMAIL_TEMPLATES_HOST_DIR:-./email-templates}`
read-only at `/email-templates` and passes `ATOM_EMAIL_TEMPLATES_DIR` through
unchanged, so this works out of the box for both the `atom` and `atom-dev`
services.
