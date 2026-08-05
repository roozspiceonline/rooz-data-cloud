FROM node:24-alpine AS deps
WORKDIR /workspace
RUN corepack enable
COPY package.json pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY apps/console/package.json apps/console/package.json
COPY packages/api-client/package.json packages/api-client/package.json
COPY packages/shared-types/package.json packages/shared-types/package.json
COPY packages/ui/package.json packages/ui/package.json
RUN pnpm install --filter @rdc/console... --no-frozen-lockfile

FROM node:24-alpine AS builder
WORKDIR /workspace
RUN corepack enable
COPY --from=deps /workspace/node_modules ./node_modules
COPY --from=deps /workspace/apps/console/node_modules ./apps/console/node_modules
COPY . .
RUN pnpm --filter @rdc/console build

FROM node:24-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /workspace/apps/console/.next/standalone ./
COPY --from=builder /workspace/apps/console/.next/static ./apps/console/.next/static
COPY --from=builder /workspace/apps/console/public ./apps/console/public
USER nextjs
EXPOSE 3000
CMD ["node", "apps/console/server.js"]
