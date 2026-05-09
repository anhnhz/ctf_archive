#!/bin/bash

if [ "$EUID" -eq 0 ]; then
    /app/cleanup_daemon.sh &
    
    ORIGINAL_FILES=(
        "/app/app.py"
        "/app/bot.py" 
        "/app/multi.py"
        "/app/requirements.txt"
        "/app/package.json"
        "/app/tailwind.config.js"
        "/app/.dockerignore"
        "/app/cleanup_daemon.sh"
        "/app/Dockerfile"
        "/app/entrypoint.sh"
    )
    
    for file in "${ORIGINAL_FILES[@]}"; do
        if [ -f "$file" ]; then
            chmod 555 "$file"
        fi
    done
    
    find /app/templates -name "*.html" -exec chmod 555 {} \; 2>/dev/null
    
    find /app/static -type f -exec chmod 555 {} \; 2>/dev/null
    
    find /app/assets -type f -exec chmod 555 {} \; 2>/dev/null
    
    chmod 755 /app
    
    touch /tmp/test_chattr
    if chattr +i /tmp/test_chattr 2>/dev/null; then
        
        for file in "${ORIGINAL_FILES[@]}"; do
            if [ -f "$file" ]; then
                chattr +i "$file" 2>/dev/null
            fi
        done
        
        find /app/templates -name "*.html" -exec chattr +i {} \; 2>/dev/null
        
        find /app/static -type f -exec chattr +i {} \; 2>/dev/null
        
        find /app/assets -type f -exec chattr +i {} \; 2>/dev/null
        
        chattr -i /tmp/test_chattr 2>/dev/null
    fi
    rm -f /tmp/test_chattr
    
    mkdir -p /home/nonroot/.cache/selenium
    chown -R nonroot:nonroot /home/nonroot/.cache
    chmod -R 755 /home/nonroot/.cache
    
    export FLAG=SECRET
    
    exec su -s /bin/bash nonroot -c "export FLAG=SECRET && cd /app && python app.py"
else
    export FLAG=SECRET
    cd /app
    exec python app.py
fi
