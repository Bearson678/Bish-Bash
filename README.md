# 50.005 Programming Assignment 2

## How to setup and run the code
1. ensure you have `> python 3.10` installed as well as `pipenv`
2. open 2 seperate terminals, and start the virtual environemnt using `pipenv shell`
3. on one terminal, run `python3 source/ServerWithoutSecurity.py`
4. in  the other terminal, run `python3 source/ClientWithoutSecurity.py`
5. you can now send messages from the client to the server 


## Sustainability

### Zip Feature
We realised that especially CP1, the asymmetric key autshentication caused file transfers to be extremely slow, so we decided to reduce file size by `zipping it`. The client will zip the file before encrypting it, and the server will first decrypt the zip file before its contents are unzipped. 


>__Test statistics__
>
>We tested on the biggest file `image.ppm`
>
>Original ~240s, with Zip ~9.59s 


### Progress Bar
We introduced a progress bar in `both client and server` to allow user to know how fast and how much their file has been sent. As the file is sent, the progres bar will fill up.

> Progress: [========================================] 100.0%


## Inclusivity 

### Language support
Everytime the user launches `either the server or client`, they will be prompted to choose their language. The server and client can have `different languages`.
>__Select your language:__
>
>1. en (english)
>2. zh (chinese)
>
>__Enter number or language code (e.g. 1 or 'en'):__ 2

This setting will be `applied to the protocol messages`, faciliating easy understanding of the authentication. 

example

<pre>
正在建立与服务器的连接...
已连接
正在发送模式 3...
正在发送模式 3...
[身份验证成功] 服务器身份已验证

服务器已验证

输入要发送的文件名（输入 -1 退出）：files/week9.html
原始文件大小 740390 bytes
压缩文件大小 : 154951 bytes
加密文件已保存
 进度: [========================================] 100.0%
文件已发送，包含 2500加密块，新大小： 154951 bytes
输入要发送的文件名（输入 -1 退出）：
</pre>
