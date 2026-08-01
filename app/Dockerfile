ARG ATOM_VERSION=dev
ARG ATOM_REVISION=unknown

FROM node:24.15.0-bookworm-slim AS base
ENV NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
RUN corepack enable

FROM base AS deps
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

FROM deps AS builder
COPY . .
RUN pnpm build

FROM node:24.15.0-bookworm-slim AS runner
ARG ATOM_VERSION
ARG ATOM_REVISION
# Labels only. The UI reads the running build from the backend's `systemStatus`
# field, so a runtime env var here would be a second, unread source of truth.
LABEL org.opencontainers.image.title="Atom UI" \
  org.opencontainers.image.version="${ATOM_VERSION}" \
  org.opencontainers.image.revision="${ATOM_REVISION}"
ENV HOSTNAME=0.0.0.0
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
WORKDIR /app

RUN groupadd --system --gid 1001 nodejs \
  && useradd --system --uid 1001 --gid nodejs nextjs

COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
CMD ["node", "server.js"]
