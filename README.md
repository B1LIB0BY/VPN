# VPN in C

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Description
My project is a secure and encrypted virtual private network (VPN) implementation. It allows users to establish secure connections over the internet using SSL based on PKI, ensuring their data privacy and confidentiality.

## Install
```
git clone https://github.com/BiliSando/VPN.git
cd VPN/
```
### Server Machine:
```
gcc -o Server Server.c -lssl -lcrypto
sudo ./Server

```
### Client Machine:
```
gcc -o Client Client.c -lssl -lcrypto
sudo ./Client

```

#### Do not use this project for a real purpose, the project was written as a personal project and not for a real purpose!
