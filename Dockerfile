FROM mcr.microsoft.com/dotnet/sdk:9.0.101 AS build

WORKDIR /src
COPY ./src/Identity.Provider/Identity.Provider/ ./

RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:9.0.0 AS runtime

WORKDIR /app
COPY --from=build /app ./

EXPOSE 8080

ENTRYPOINT ["dotnet", "IdentityProvider.dll"]
