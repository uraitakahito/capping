# capping — local wacz-auth signing service.
#
# Multi-stage: build TypeScript in one image, ship dist/ plus its runtime
# dependencies and openssl in the next.
#
# The npm side is one package — commander, for the CLI. Nothing cryptographic
# comes from npm: key generation, certificates, digests, signatures and
# RFC 3161 are openssl invocations, and openssl comes from apt.

FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm run build

# The production tree, built in a stage of its own from nothing.
#
# Not `pnpm deploy`, which BrowserHive uses: that selects a project out of a
# workspace, and capping's pnpm-workspace.yaml declares no packages — it exists
# only for allowBuilds and enablePrePostScripts, so `deploy` stops with
# ERR_PNPM_NOTHING_TO_DEPLOY.
#
# Nor `pnpm install --prod` on top of the build stage: pruning rewrites a
# node_modules holding 146 dev packages, and committing that layer wedged the
# builder for twenty minutes with the install itself reporting "Done in 267ms".
# Installing into an empty stage writes one package and nothing else.
#
# --node-linker=hoisted because pnpm's default layout is symlinks into a store
# that the runtime stage will not have.
FROM node:24-bookworm-slim AS deps
WORKDIR /deps
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --prod --frozen-lockfile --node-linker=hoisted

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production

# node:24-bookworm-slim does NOT ship the openssl CLI — measured, not assumed:
#
#   $ container run --rm node:24-bookworm-slim command -v openssl
#   sh: 1: openssl: not found
#
# Node links against libssl, which is a different thing. capping shells out for
# every cryptographic step, so without this package the image builds cleanly and
# then fails on the first request.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=deps /deps/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# The identity is mounted, not baked. Generating one at startup would give a
# different CA on every boot, which makes `capping verify --root` impossible to
# write down — and being able to write it down is the point of a dev CA.
VOLUME ["/id"]

# 0.0.0.0, not the 127.0.0.1 default: another container has to reach this.
EXPOSE 8080
ENTRYPOINT ["node", "dist/cli.js"]
CMD ["serve", "--dir", "/id", "--host", "0.0.0.0", "--port", "8080"]
