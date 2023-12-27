import requests
#Breakpoint Transmission
url='http://127.0.0.1:8080/client1/a.txt'

data={}
headers={"Authorization": "Basic Y2xpZW50MToxMjM=",
         "Range": "bytes=0-1,1-2,2-3"}
r=requests.get(url=url, data=data, headers=headers)
print(r)
# print the complete request url with parameters
print(r.url)

print(r.content.decode())