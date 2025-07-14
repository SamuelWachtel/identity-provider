FROM mcr.microsoft.com/dotnet/sdk:9.0-preview AS build
COPY https-dev-cert.pfx /https-dev-cert.pfx
WORKDIR /src
COPY ./src/Identity.Provider/Identity.Provider/ ./
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:9.0-preview AS runtime
WORKDIR /app
COPY --from=build /app ./
EXPOSE 5013
ENTRYPOINT ["dotnet", "IdentityProvider.dll"]
