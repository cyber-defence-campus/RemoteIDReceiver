## Run Application

Run python script:
```bash
sudo python3 ./Receiver/backend/dronesniffer/main.py -p 80
```
The frontend of the application will run on localhost:80 or the specified port.

*Note:* It needs to be run with `sudo` since the wifi interfaces requires privileges to work in monitor mode.



When running the app via the `dsniffer.service` the app can be relaunched by restaring the service:
```
sudo systemctl stop dsniffer.service
sudo systemctl start dsniffer.service
```

## Docker Compose Usage

The project includes a Docker Compose configuration that allows you to easily select which frontend style to use.

### Usage Options

1. Using Google Maps style:
   ```bash
   docker-compose up google-maps
   ```

2. Using Swiss Satellite style:
   ```bash
   docker-compose up swiss-satellite
   ```

3. Using a custom style URL:
   ```bash
   STYLE_URL=example.com docker-compose up custom
   ```

To rebuild a service after changes:
```bash
docker-compose up --build google-maps
```

