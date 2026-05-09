from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
import sys
import os


def visit_and_clean(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
        
    chrome_options.binary_location = "/usr/bin/chromium"

    driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get(url)

        driver.add_cookie({
                "name": "FLAG",
                "value": os.environ.get("FLAG", None),
                "path": "/",
                "httponly": False,
                "secure": False
            })
        driver.refresh()

        time.sleep(2)  

    finally:
        driver.quit()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bot.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    visit_and_clean(target_url)
