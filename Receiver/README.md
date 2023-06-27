# Monitor Drones

## Run Application

**_IMPORTANT:_** due to relative paths, within the application, the 
application has to be started while in this directory 
`/workspace`.

The application can be manually started by using a shell script `run-demo.sh`. 
The script uses the Pipfile.lock to create a virtual environment, install 
all required dependencies and then start the application. The application 
can be started in two different modes:
 - pcap file-mode and
 - interface-mode

which will be explained in detail below.

The frontend of the application will run on [localhost:8080](127.0.0.1:8080).
A documentation of the API can be found on 
[localhost:8080/docs](127.0.0.1:8080/docs) while the application is running.

### Pcap file-mode

terminal command:
```bash
./backend/dronesniffer/run-demo.sh
```

The pcap file-mode requires a pre-captured pcap-file. The subdirectory 
`./backend/dronesniffer/resources` contains example pcap-files, which can be 
used. Per default the pcap file `alessa_beacon.pcapng` is used. Currently, 
other files can only be selected if the corresponding code section is adjusted.

To use another file, change the value of the`file`-variable (on row 58) in the 
file `/backend/dronesniffer/drone_sniffer.py` to the desired file path. and 
restart the application with the above-mentioned command. 

### Interface-mode

terminal command:
```bash
./backend/dronesniffer/run-demo.sh -i <interface-name>
```

With the `-i`-flag the application will sniff in real-time on the selected 
interface. If no value is passed down for the `<interface-name>` a default 
interface _wlx801f02f1e3c9_ will be used. Currently, this can not be 
overwritten.
 
The interface will be set to monitor mode, which requires root privileges.

## Backend

See 
[README.md](https://github.com/cyber-defence-campus/2023_Mueller-Fabia_Brunner-Sebastian_DroneID-Monitoring/tree/main/workspace/backend/README.md) 
in directory `/backend`.

## Frontend

The frontend uses the Vue.js Framework and [uvicorn](https://www.uvicorn.org/) 
as a web server implementation.


### Development: start frontend 

run command: `uvicorn main:app`

main stands for the python-file name and app for the FastAPI object created.

during development, you may use `uvicorn main:app --reload`. With the 
`--reload` option appended it will restart the server every time a change 
in the code has been made.

- /docs displays API documentation (OpenAPI)


# Spoof Drones

**_IMPORTANT:_** To execute the script to spoof drones, root privilege and 
a WI-FI adapter is required.

To spoof a drone the following command can be executed in a terminal (from 
the directory `/workspace`):
```bash
sudo python3 ./spoof_drones.py
```

The script will automatically spoof a drone, which can be monitored via the 
app. To identify the drone, it will receive a unique serial number. The 
script will run indefinitely and send RemoteId packets until it is interrupted.

### Script Flags:

The script can be customized with the following parameters.

| Flag short | Flag extended | Parameter                  | Default                                           | Description                                    |
|------------|---------------|----------------------------|---------------------------------------------------|------------------------------------------------|
| `-h`       | `--help`      | -                          | -                                                 | Displays help message                          |
| `-i`       | `--interface` | `n`: str                   | wlx00c0ca99160d                                   | Interface name                                 |
| `-m`       | `--manual`    | -                          | -                                                 | Spoof one drone and control its movement       |
| `-r`       | `--random`    | `m`: int                   | 1                                                 | Spoof `m` drones that move automatically       |
| `-s`       | `--seconds`   | `s`: int                   | 3                                                 | Time between sending packets                   |
| `-l`       | `--location`  | `lat`: int <br> `lng`: int | 47.3763399, 8.5312562 <br/> Kasernenareal, Zurich | Latitude and Longitude of drone starting point |

