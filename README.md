# CS305-Project

**This is the final project of Computer Network 2023Fall course (CS305) of SUSTech.**

## 开发日志
#### 12.28
当client发送一个get请求时，假设请求头第一行是`GET /client1/aaaa HTTP/1.1`，然后server给他返回一个html，里面包含了两个链接：

```
<li><a href="/client1/aaaa/aaaaa.txt">a.txt</a></li>
<li><a href="client1/aaaa/bbb.txt">b.txt/</a></li>
```

这两个的区别是，第一个最前面有/，而第二个没有。

然后client点击这两个链接，会发送如下请求：

第一个：`GET /client1/aaaa/a.txt HTTP/1.1`

第二个：`GET /client1/client1/aaaa/b.txt HTTP/1.1`

显然, 第二个是有问题的, 返回404.

原因在于:

**绝对路径链接：链接以斜杠 / 开头，表示该链接是相对于网站根目录的绝对路径。比如，/client1/aaaa/a.txt 将被解释为 `http://localhost:8080/client1/aaaa/a.txt`，无论当前页面的 URL 是什么。它指向网站根目录下的特定路径**

**相对路径链接：链接没有以斜杠 / 开头，表示相对于当前页面的路径。比如，client1/aaaa/b.txt 将被解释为相对于当前页面的路径，链接到当前页面所在目录下的 client1/aaaa/b.txt 文件**

而回到最开始的那个get请求`GET /client1/aaaa HTTP/1.1`, 注意到这是的当前目录其实是/client (然后请求获取其中的aaaa)。因此，第二个被拼接成 `/client1` + `/` +`client1/aaaa/bbb.txt`

#### 12.29

![](https://cdn.jsdelivr.net/gh/Evan-Sukhoi/ImageHost@main/img/20231230001248.png)

## Copyright Info
This project uses icons for HTML from:
<a href="https://www.flaticon.com/free-icons/add-list" title="add list icons">Add list icons created by HideMaru - Flaticon</a>
