import requests
import json

offset = 0
limit = 50
f = open('users.csv', 'w')
while offset < 2750:
    url = "https://app.contrastsecurity.com/Contrast/api/ng/superadmin/users?expand=groups,skip_links&limit=%d&offset=%d&quickFilter=ALL&searchKey=&sortRow=" % (limit, offset)
    headers = {
        "Cookie": "JSESSIONID=094D16955CA09C9F40C6D9B89398CCEF; AWSELB=539F750F10478D4E063589242269EA3B38F3BDF0DC1CD2ADE18104255607CEFB33EAFBA1524FDBF3CB106E5510B99D15D49704F2C7C558167B095D416CD8AD46A877E622257D192B343C69838FECF44FA7CA479693; XSRF-TOKEN=1050853df1c92450c6a5c7afb8c5ee13; contrast_admin_ui_key=\"eyJzdGFydCI6MTUxMTkxNzM4OTM0MiwibGFzdEFjdGl2aXR5IjoxNTExOTE3NDk3NzA0LCJpZGxlVGltZW91dCI6MTgwMCwiYWJzb2x1dGVUaW1lb3V0IjoyODgwMH0=\"; hsfirstvisit=https%3A%2F%2Fwww.contrastsecurity.com%2F|https%3A%2F%2Fwww.google.com%2F|1480365882886; __hstc=92971330.91b755897ce3c142f0c2482ad1171bc1.1480365882888.1480451518190.1480604510101.6; hubspotutk=91b755897ce3c142f0c2482ad1171bc1; _ga=GA1.2.254652096.1480368546; messagesUtk=91b755897ce3c142f0c2482ad1171bc1; BAYEUX_BROWSER=15nnyozq0oilv55f",
        "X-XSRF-TOKEN": "1050853df1c92450c6a5c7afb8c5ee13",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.59 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://app.contrastsecurity.com/Contrast/static/ng/admin_index.html",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive"
    }
    a = requests.get(url=url, headers=headers)
    users = json.loads(a.text)
    for user in users['users']:
        try:
            if user['last_login'] > 0:
                linetowrite = user['organizations'][0]['organization']['name'] + ',' + user['first_name'] + ',' + user['last_name'] + ',' + user['uid'] + ',' + '\n'
                print(linetowrite)
                f.write(linetowrite)
        except:
            continue
    offset += limit
f.close()


