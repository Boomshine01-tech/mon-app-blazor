# Étape 1 : Build de l'application
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copier le fichier projet et restaurer les dépendances
COPY ["Server/SmartNest.Server.csproj", "Server/"]
RUN dotnet restore "Server/SmartNest.Server.csproj"

# Copier tout le code du serveur
COPY Server/ Server/

# Builder l'application
WORKDIR "/src/Server"
RUN dotnet build "SmartNest.Server.csproj" -c Release -o /app/build

# Étape 2 : Publication
FROM build AS publish
RUN dotnet publish "SmartNest.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Étape 3 : Image finale runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Créer le dossier pour la base de données SQLite
RUN mkdir -p /app/data

# Variables d'environnement pour optimisation mémoire (512 MB Render)
ENV DOTNET_GCHeapHardLimit=400000000
ENV DOTNET_GCConserveMemory=9
ENV ASPNETCORE_URLS=http://0.0.0.0:$PORT
ENV ASPNETCORE_ENVIRONMENT=Production

# Exposer le port (dynamique sur Render via $PORT)
EXPOSE $PORT

# Copier les fichiers publiés
COPY --from=publish /app/publish .

# Point d'entrée de l'application
ENTRYPOINT ["dotnet", "SmartNest.Server.dll"]