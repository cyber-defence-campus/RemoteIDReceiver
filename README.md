# Drone Remote ID Monitoring System
This repository is the public repository for the Bachelor Thesis on a "Building an Accessible and Affordable Drone Monitoring System Based on Remote ID". It contains code and documents related to the web application developed as part of this bachelor's thesis. The contents are organized as follows:

+ The **Bachelor_Thesis.pdf** is the final report of the project.
+ The **Receiver** folder contains all the code for the developed web application.

This system was developed to monitor drones via Remote IDs. The 
system supports DJI's proprietary format as well as the ASD-STAN format. 
It currently monitors drones via Remote IDs transmitted over Wi-Fi. It is designed to 
be easily extended with additional formats as well as 
sniffing types.

**Disclaimer:** This repository was created by students as part of a Bachelor thesis. It is not meant to be maintained nor updated.


**Note:** A spoofer program,  which is able to spoof fake Remote ID information is kept in a separate repository. The spoofed Remote IDs can be DJI's proprietary format as well as the ASD-STAN format and can be used to test the drone monitoring system in this repository.

## Authors
The work in this project was  done by:
- [Fabia Müller](https://github.com/alessmlr), Zurich University of Applied Sciences
- [Sebastian Brunner](https://github.com/Wernerson),Zurich University of Applied Sciences

and supervised by:
- [Prof. Dr. Marc Rennhard](https://github.com/rennhard),  Zurich University of Applied Sciences
- [Llorenç Romá](https://github.com/llorencroma),  Cyber-Defence Campus
  
## Installation 
The system is meant to run in any Linux distribution. We tested it on a Raspberry Pi 4 running a Lite OS 64-bit.

Execute install script with

   ```
    sudo sh install.sh
   ```
 
   (This step requires a working internet connection)

After the installation script is through, the sniffer service will start and the web application should be 
available via <host>.local in the browser, accessible from any device connected to the same network.

## Usage

Whenever a browser accesses the application for the first time, a setup 
view appears (see below), requesting a google maps key.

![Setup view](Receiver/resources/images/setupview.png "Setup view")

After the google maps key is accepted a map appears with multiple controls. The 
picture below displays this view (monitor view). To start monitoring, 
an WLAN interface (**with monitor mode capabilities**) has to be chosen via the Settings (in the top left corner) 
and saved. Since it is a google maps beneath, two map options (Regular and 
Satellite) above the Settings are available.

![Monitor view of active system displaying both map options - Regular and Sattelite](Receiver/resources/images/monitorview.png "Monitor view")

Actively monitored drones are listed in the list in the bottom left corner. 
Optionally the flown path of the drone as well as the pilot location 
("P"-pin) and the starting point (home location, "H"-pin). Each drone 
receives its own colour to distinguish the different drones. To display drone details, 
simply click on the drone.

An already completed flight of a drone can be replayed by the "play"-button 
displayed in the metrics data of the drone. This can be opened by either 
clicking on a drone or via the "Active Drones" list and clicking the 
metrics-emoji.

![Replay view](Receiver/resources/images/replayview.png "Replay view")


For further instructions please read the [Wiki](https://github.com/cyber-defence-campus/RemoteIDReceiver/wiki) or Section 5.2.2 of [the Bachelor thesis](Bachelor_Thesis_Drone_Monitoring_System.pdf).
