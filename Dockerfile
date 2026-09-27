# The login app. Multi-arch, the shape of odin-core's Dockerfile-identity-host. odin-core is cloned
# at the commit in odin-core.ref, because the app references two of its projects (see
# Directory.Build.props). Build:
#   docker build --build-arg ODIN_CORE_SHA=$(cat odin-core.ref) -t odin-oidc-login .
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:9.0 AS build
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
      --configuration Release --warnaserror -a "$TARGETARCH" -o /out

FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /out .
# Behind a TLS-terminating proxy; Broker:CertificatePath unset means plain http here.
ENV ASPNETCORE_URLS=http://+:8080
ENV Broker__KeyRingPath=/keys
VOLUME /keys
EXPOSE 8080
ENTRYPOINT ["dotnet", "Odin.Oidc.Login.dll"]
