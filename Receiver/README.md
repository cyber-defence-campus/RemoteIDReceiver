## Run Application

The application can be manually started by restarting the `dsniffer.service` service or running the python script `/backend/dronesniffer/main.py`. 

Run python script:
```bash
python3 /backend/dronesniffer/main.py -p 80
```

or restart service:
```
systemctl daemon-reload
systemctl enable dsniffer
systemctl start dsniffer
```
The frontend of the application will run on localhost:80 or the specified port.

*Note:* It needs to be run with `sudo` since the wifi interfaces requires privileges to work in monitor mode.
