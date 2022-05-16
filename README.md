# proxy-auth-injector

The program is a bandaid for applications that don't support proxies with username/password authentication (I'm looking at you Chrome). This program will look like a normal proxy to the application you're working with. But behind the scenes, it's relaying each request to the acutal proxy you want while adding the necessary username/proxy authentication.

# Usage

```
make
./proxy <localport> <remoteproxy_ip> <remoteproxy_port> <username:password>
```

Then direct your application to use ```127.0.0.1:4321``` as the proxy if ```4321``` was the local port you specified. For example, for Chrome you would add the flag ```--proxy-server=http://127.0.0.1:4321```

# TODO

- Look into using splice and pipes to avoid kernel to userspace copy.
