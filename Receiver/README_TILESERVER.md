# Setup Offline Map
If you want to provide offline functionality, you can follow this guide to install a offline map server.


## Map Download
The first step is to download the map data. [PlanetOSM](https://planet.openstreetmap.org/pbf/) is a great source to download valid .osm.pdf files. You can either get the whole globe or search for files of your country.


## Conversion
Once the raw data is downloaded, it needs to be processed into vector tiles. Tilemaker is an open-source tool that can convert from the PBF format to the MbTiles or PmTiles format. 

The command used to generate the vector tiles is:

```bash
docker run -it --rm -v \$(pwd):/data ghcr.io/systemed/tilemaker:master /data/planet-250519.osm.pbf --output /data/globe.mbtiles
```
*Note: Be sure to adjust the input file name. This command creates a file *globe.mbtiles*.*

## Host
The next step is to serve the generated vector tiles via an HTTP server. Tileserver GL is a map server that can be used to host and serve these tiles to the frontend. The server runs locally and exposes endpoints that the frontend map library can consume.


```bash
docker run --rm -it -v \$(pwd):/data -p 8080:8080 maptiler/tileserver-gl:latest --file globe.mbtiles
```

MapTile generates an endpoint to inspect the map data at localhost:8080. You can now adjust the '.env' file by uncommenting the following line and running the build process.

```env .env
# FILE: .env
FRONTEND_MAP_SOURCE=http://localhost:8080/styles/512/basic-preview.json 
```
```bash
docker-compose up build-frontend
```