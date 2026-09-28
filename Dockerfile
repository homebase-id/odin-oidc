# The login app. Multi-arch, the shape of odin-core's Dockerfile-identity-host. odin-core is cloned
# at the commit in odin-core.ref, because the app references two of its projects (see
# Directory.Build.props). Build:
#   docker build --build-arg ODIN_CORE_SHA=$(cat odin-core.ref) -t odin-oidc-login .
# Plain `docker build` leaves TARGETARCH empty and publishes for the host; `docker buildx build
# --platform linux/arm64` sets it and cross-compiles.
FROM mcr.microsoft.com/dotnet/sdk:9.0@sha256:01fabc4758d1d74e39eda700c8463dae6241a61481f973683692ddcb59a5eeb7 AS build
ARG TARGETARCH
ARG ODIN_CORE_SHA
ARG ODIN_CORE_REPO=https://github.com/homebase-id/odin-core.git
RUN test -n "$ODIN_CORE_SHA" || (echo "ODIN_CORE_SHA build arg is required (cat odin-core.ref)" && exit 1)

WORKDIR /build
RUN git clone --filter=blob:none --no-checkout "$ODIN_CORE_REPO" odin-core \
 && git -C odin-core checkout --quiet "$ODIN_CORE_SHA"

COPY . odin-oidc
WORKDIR /build/odin-oidc
RUN dotnet publish src/Odin.Oidc.Login/Odin.Oidc.Login.csproj \
      --configuration Release --warnaserror ${TARGETARCH:+-a $TARGETARCH} -o /out

FROM mcr.microsoft.com/dotnet/aspnet:9.0@sha256:2680706c9656fafe34876446d694fd25077fd0b5da478f38d56073ac6c21d37e
WORKDIR /app
COPY --from=build /out .
# Behind a TLS-terminating proxy: plain http on the image's default port 8080, Kestrel's own
# certificate config unused. Runs as the image's unprivileged `app` user; /keys is the Data
# Protection key ring, the one thing written.
RUN mkdir /keys && chown app:app /keys
USER app
ENV Broker__KeyRingPath=/keys
VOLUME /keys
EXPOSE 8080
ENTRYPOINT ["dotnet", "Odin.Oidc.Login.dll"]
