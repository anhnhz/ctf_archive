#!/bin/bash

UPLOAD_DIR="/app/upload"

while true; do
    if [ ! -d "$UPLOAD_DIR" ]; then
        sleep 15
        continue
    fi

    if [ "$(ls -A $UPLOAD_DIR 2>/dev/null)" ]; then
        rm -rf $UPLOAD_DIR/*
        
        mkdir -p $UPLOAD_DIR/quarantine
        mkdir -p $UPLOAD_DIR/temp
        
        chown -R nonroot:nonroot $UPLOAD_DIR
        chmod 755 $UPLOAD_DIR $UPLOAD_DIR/quarantine $UPLOAD_DIR/temp
    fi
    
    sleep 15
done
