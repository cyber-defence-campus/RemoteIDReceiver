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

