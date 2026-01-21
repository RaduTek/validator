#!/bin/bash

sudo cp validator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable validator.service
sudo systemctl start validator.service
sudo systemctl status validator.service