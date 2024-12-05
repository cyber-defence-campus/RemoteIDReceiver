# Drone Remote ID Monitoring System

+ The **Receiver** folder contains all the code for the developed web application.

This system was developed to monitor drones via Remote IDs. The 
system supports DJI's proprietary format as well as the ASD-STAN format. 
It currently monitors drones via Remote IDs transmitted over Wi-Fi. It is designed to 
be easily extended with additional formats as well as 
sniffing types.


  
## Installation

The system is meant to run in any Linux distribution. We tested it on a Raspberry Pi 4 running a Lite OS 64-bit and on an Ubuntu 22.04. Make sure you have `python` and `pip` installed. 

## Important 

If you are intending on installing on a Raspberry Pi you will need to enable a method of Wlan monitoring. This can be done via software or via hardware. The hardware option costs around $10. 

### Hardware 

We recommend the **EDIMAX EW-7811UN** although any wireless adapter with monitoring mode is suitable

**If installing using additional hardware please follow these steps to ensure your wireless adapter is visible, if using software only (Pi 4 or Pi5 then skip to Installation section**

**Plug your ethernet cable and USB wireless adapter in to the Pi and then boot** 

SSH in to your Pi 
```
ssh pi@raspberrypi
```
Once you’re logged in to the Pi, check to see if the Pi recognizes the USB device using the following command:
```
lsusb
```
You should see the following:
```
Bus 001 Device 004: ID 7392:7811 Edimax Technology Co., Ltd EW-7811Un 802.11n Wireless Adapter [Realtek RTL8188CUS]
Bus 001 Device 003: ID 0424:ec00 Standard Microsystems Corp. SMSC9512/9514 Fast Ethernet Adapter
Bus 001 Device 002: ID 0424:9514 Standard Microsystems Corp.
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
```
Notice the first line.

Now we’ll check to see if the device drivers are loaded. To list the kernal modules use:

```
lsmod
```

You should see something like:

```
Module                                   Size              Used by
cfg80211
rfkill
8192cu       
bcm2835_gpiomem
```

8192cu is what we’re looking for, and it looks like it’s installed

As a final check, run:

```
iwconfig
```

And you should see the wireless adapter here:

```
wlan0     unassociated  Nickname:"<WIFI@REALTEK>"
          Mode:Managed  Frequency:2.462 GHz  Access Point: 20:3D:66:44:C6:70
          Bit Rate:72.2 Mb/s   Sensitivity:0/0
          Retry:off   RTS thr:off   Fragment thr:off
          Power Management:off
          Link Quality=100/100  Signal level=100/100  Noise level=0/100
          Rx invalid nwid:0  Rx invalid crypt:0  Rx invalid frag:0
          Tx excessive retries:0  Invalid misc:0   Missed beacon:0
```

It is important to note the first line, here is its "wlan0" on some it may show as "wlan1"

Now, open the following file to add our network credentials.

```
sudo vim /etc/wpa_supplicant/wpa_supplicant.conf
```

add

```
network={
  ssid="YOUR_NETWORK_SSID"
  psk="YOUR_NETWORK_PASSWORD"
}
```
Of course, you’ll need to substitute your SSID and password.

Remove the ethernet cable, and reboot with the following command:

```
reboot
```

Ensuring the adapter does not go in to sleep mode

```
sudo nano /etc/modprobe.d/8192cu.conf
```

Add the following two lines to the configuration file, save and exit
```
# Disable power management
options 8192cu rtw_power_mgnt=0 rtw_enusbss=0
```
```
sudo reboot
```


### Installation (Start here for software only, continue from here for hardware)

**Note, this software changes the wlan0 function to monitor mode. You will therefore need to ensure that you can SSH in to the Pi as direct connectivity will not be possible** 

**Install Aircrack-ng**

```
wget https://download.aircrack-ng.org/aircrack-ng-1.7.tar.gz
 tar -zxvf aircrack-ng-1.7.tar.gz
 cd aircrack-ng-1.7
sudo apt-get -y install libnl-3-dev
sudo apt-get -y install libnl-genl-3-dev
sudo apt-get -y install libssl-dev
 autoreconf -i
 ./configure --with-experimental
 make
 make install
 ldconfig 
```

# Alternative Installation Using Kali Linux Image 

Download the correct image for your Pi from here https://arm.kali.org/images.html and spin up a deployment on your PI using this as a custom image

```
 sudo apt-get update && sudo apt-get upgrade
```
```
sudo apt-get install -y aircrack-ng
```

# After Installing Aircrack 

**Configure** 

Check to determine the name assigned to your wlan. By default it will normally be wlan0, if it is not then use whatever "wlan" has been assigned. For hardware installation ensure you use the wlan for the wireless adapter.
```
airmon-ng
```

Kill other processes using the wlan interface
```
airmon-ng check kill
```

SWitch wlan0 to monitor mode (change wlan0 to the correct wlan number assigned to your wireless adapter)
```
airmon-ng start wlan0
```
**To exit monitor mode and restore original functionality** 

```
airmon-ng stop wlan0mon
```
```
service network-manager start
```

## Installing RiD Service 

**SSH in to your Pi**

Clone in to the repository 
```
sudo git clone https://github.com/DeFliTeam/RemoteIDReceiver
```


From `Receiver/` folder install the requirements with
```
cd RemoteIDReceiver/Receiver
```
```
sudo pip3 install -r ./requirements.txt
```
   (This step requires a working internet connection) **If you get an error regarding python and a virtual environment please use the fix here https://github.com/DeFliTeam/RemoteIDReceiver#error-when-installing-requirementstxt**

To start the application manually run the python script (port 80 by default but you can change if required):

```
sudo python3 ./backend/dronesniffer/main.py -p 80
```

This will start the web application on port 80 or the port defined by your previous command.

**required** The receiver app can also be run at boot time by enabling `dsniffer.service`,  which runs the main python script. To run the service at boot time execute the following command

   ```
    sudo sh install_service.sh
   ```
 
This script copies the receiver files into `/opt/dsniffer/` and enables the service to be run at boot time. 

**AT THIS POINT YOU WILL NEED TO EMAIL US TO OBTAIN THE DETAILS FOR SENDING DATA team@defli.xyz.
Please note that the email you use for sending must be replicated in the fields marked   You can however skip the sending data part for now and move on to the Usage Section**

## Sending Data ## 

To send the data to our server please follow the follwing instructions. 

### Create SSH Key ###

Check for existing key pair 

```
ls -al ~/.ssh/id_*.pub
```

If there are existing keys, you can either use those and skip the next step or backup up the old keys and generate a new one.

If you see No such file or directory or no matches found it means that you do not have an SSH key and you can proceed with the next step and generate a new one.

The following command will generate a new 4096 bits SSH key pair with your email address as a comment. **Remember to put your email address in**

```
ssh-keygen -t rsa -b 4096 -C "YOUR_EMAIL"
```
Press Enter to accept the default file location and file name:

```
Output- Enter file in which to save the key (/home/yourusername/.ssh/id_rsa):
```

Next, the ssh-keygen tool will ask you to type a secure passphrase, please do not enter a passphrase, simply press "enter" twice.

To be sure that the SSH keys are generated you can list your new private and public keys with:

```
ls ~/.ssh/id_*
```
The output will look like this 
```
/home/yourusername/.ssh/id_rsa /home/yourusername/.ssh/id_rsa.pub
```

Now that you have generated an SSH key pair, you need to copy the public key to the DeFli server

```
ssh-copy-id root@172.24.239.135
```

You will be prompted for a password, this will be assigned to you via email 

If this does not work please try this command instead 

```
cat ~/.ssh/id_rsa.pub | ssh ssh root@167.88.44.121 "mkdir ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```


### Sending Data ###

```
ssh ssh root@167.88.44.121 "mkdir -p home/user/YOUR_EMAIL"
```

```
crontab -e
```

```
*/1 * * * *  rsync -avz ssh root@167.88.44.121:/home/user/YOUR_EMAIL /opt/dsniffer/remoteid.db
```




## Usage

From the browser, access the ip address of the receiver machine on the specified port. Whenever a client browser accesses the application for the first time, a setup view appears (see below), requesting a google maps key ([see how to get you Google Maps API](https://developers.google.com/maps/documentation/javascript/get-api-key)). 

**Note** Some browser might not show the GUI properly. See section **Brower Issues** for known issues.

![Setup view](Receiver/resources/images/setupview.png "Setup view")

After the google maps key is accepted a map appears with multiple controls. The 
picture below displays this view (monitor view). 

**To start monitoring, a WLAN interface (**with monitor mode capabilities**) has to be chosen via the Settings (in the top left corner) and saved**

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

## Troubleshooting
### Browser issues
During the tests different clients were tested, including laptops and an iPad Air 4th Generation as well as different browsers which successfully worked. Minor issues were noted:

- Ubuntu laptop running **Mozilla Firefox 103.0.1** did not load the inital view for configuring the Google API.
- iPad running **Safari** showed minor graphic isseus with the drone path.

### Error when installing requirements.txt
With a newer version of `pip` we encountered the following error when running `pip3 install -r requirements.txt`:

`error: externally-managed-environment`

Executing the following command solved it, but we did not investigate further:

`sudo mv /usr/lib/python3.11/EXTERNALLY-MANAGED /usr/lib/python3.11/EXTERNALLY-MANAGED.old`
