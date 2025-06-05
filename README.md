# 🛰️ Drone Remote ID Monitoring System

This repository introduces an extended **Remote ID Monitoring Platform** developed as part of a bachelor thesis at the **Lucerne University of Applied Sciences and Arts**, in collaboration with the **Cyber Defence Campus**. The system enables offline-capable, real-time and replayable monitoring of civilian drone broadcasts as required under the **ASD-STAN prEN 4709-002** standard.

The project builds on the original [Remote ID Receiver](https://github.com/cyber-defence-campus/RemoteIDReceiver), adding full ASD-Stan support, multithreaded performance, and a user-friendly offline mapping frontend.

## 🧠 Project Summary

Modern drones are increasingly required to broadcast identification messages (Remote ID) in open formats over Wi-Fi or Bluetooth. This system captures, decodes, stores, and visualizes such messages using:

- A modular **Python backend** with REST + WebSocket APIs
- A **VueJS-based frontend** with customizable map source (via MapLibre JS)
- Full support for **all ASD-STAN Remote ID message types**
- **Replay mode** for investigating previous drone activities

## 📦 Installation

To install and run the project, please follow the instructions in the official [Receiver/README.md](https://github.com/cyber-defence-campus/RemoteIDReceiver/blob/main/README.md).

This includes setting up:

- A compatible Wi-Fi adapter in monitor mode 
- Python and NodeJS environments for backend/frontend
- Optional: Hosting your own [TileServer](./Receiver/README_TILESERVER.md) for offline maps

## 🚀 Usage

### Monitor Mode

Live view of all currently broadcasting drones, updated in real-time.

![Monitor view](Receiver/resources/images/screen_live.png "Monitor view")

### Replay Mode

Reconstruct and analyze past drone broadcasts based on stored data.

![Replay view](Receiver/resources/images/screen_replay.png "Replay view")

## 👥 Authors & Supervision

This project was implemented as part of a **Bachelor thesis** in the BSc AIML program at Lucerne University.

- **Author**: [Sven Fahrni](https://github.com/svenfahrni)
- **Supervisor CYD**: [Llorenç Romá](https://github.com/llorencroma), Cyber Defence Campus
- **Supervisor HSLU**: [Thomas Letsch](https://www.ost.ch/de/person/thomas-letsch-1402)

