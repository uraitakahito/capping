# capping — local wacz-auth signing service.
#
# Multi-stage: build TypeScript in one image, ship dist/ plus openssl in the
# next. There is no `npm ci --omit=dev` step in the runtime stage because there
# is nothing to install — capping has no runtime dependencies at all. Its one
# dependency is openssl, and that comes from apt rather than npm.

FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN pnpm run build

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
