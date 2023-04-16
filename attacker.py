import winreg, os


def geolocation():
    """
    Return latitute/longitude of host machine (tuple)
    """
    import sys
    import json

    if sys.version_info[0] > 2:
        from urllib.request import urlopen
    else:
        from urllib2 import urlopen
    response = urlopen("http://ipinfo.io").read()
    json_data = json.loads(response)
    latitude, longitude = json_data.get("loc").split(",")
    return (latitude, longitude)


print(os.getcwd())

reg_hkey = winreg.HKEY_CURRENT_USER
key = winreg.OpenKey(
    reg_hkey, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ
)
index = 0
while True:
    v = winreg.EnumValue(key, index)
    print(index, " ", v)
    index += 1
