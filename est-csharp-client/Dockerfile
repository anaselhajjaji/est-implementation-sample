FROM mcr.microsoft.com/dotnet/core/runtime:3.1-buster-slim AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["EstClient.csproj", ""]
RUN dotnet restore "./EstClient.csproj"
COPY . .
WORKDIR "/src/."
RUN dotnet build "EstClient.csproj" -c Release -o /app/build

FROM build AS publish
# dotnet publish
RUN dotnet publish "EstClient.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "EstClient.dll"]