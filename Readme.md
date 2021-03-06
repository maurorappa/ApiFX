

# APIFX - API Firewall for NginX


![logo](apifx.jpg)

APIFX leverages NGINX features to provide a complete security solution using Auth Request Module.
TLS (and mtls) is completely handled by nginx so it is no part of this software 
 
Every call is verified by an external web service listening in the same container (for performance reason) 
This service check the client IP and the URI, it can apply rate limiting per incoming IP and it could also perform paramter/body inspection.
It has a basic set of API for configuration and a Prometheus endpoint for access metrics.



It is written in simple plain code but optimized for speed, the logic is clearly understandable and all functions are easy to understand.

It periodically caches the runtime confuration on disk and check at every startup, so in case of a crash it will load a configuration not older than 30 seconds.

The URI filter is based on swagger file (https://xxxx.com/docs/swagger.json) which is automatically parsed; there is no need to define manually any URL and a reload can be triggered via an API endpoint.
For now, the program checks only the method and URL accessed but it can be easily extended to check parameters and even the body.

There are 2 modes of operation: pass-through and enforcing.
In the first mode all requests are allowed and simply logged; in the second every call is evaluated according to ther defined rules.

There are two categories of IP, one set is without any rate limiting and another requires to define a rate per second.

## Usage

For now, this container will ship a full simulation setup.

Start the docker image with various port-forwarding. Supervisord will start Nginx, Apifx and an api mock service
Check its log, apifx will show all urls allowed from the swaggwr file.

```
% docker run -it -p 80:80 -p 5001:5001 -p 5002:5002 -p 8080:8080 apifx:latest

2020-07-18 09:30:23,087 INFO Set uid to user 0 succeeded

2020-07-18 09:30:23,095 INFO supervisord started with pid 1

2020-07-18 09:30:24,098 INFO spawned: 'apifx' with pid 7

2020-07-18 09:30:24,103 INFO spawned: 'nginx' with pid 8

2020-07-18 10:17:07,724 INFO spawned: 'mockapi' with pid 9

2020/07/18 10:17:07 listening to 8080

2020/07/18 09:30:24 [notice] 8#8: using the "epoll" event method

2020/07/18 09:30:24 [notice] 8#8: nginx/1.19.1

2020/07/18 09:30:24 [notice] 8#8: built by gcc 9.2.0 (Alpine 9.2.0) 

2020/07/18 09:30:24 [notice] 8#8: OS: Linux 4.19.76-linuxkit

2020/07/18 09:30:24 [notice] 8#8: getrlimit(RLIMIT_NOFILE): 1048576:1048576

2020/07/18 09:30:24 [notice] 8#8: start worker processes

2020/07/18 09:30:24 [notice] 8#8: start worker process 12

2020/07/18 09:30:24 Config dump not found on disk

2020-07-18 09:30:25,137 INFO success: apifx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

2020-07-18 09:30:25,137 INFO success: nginx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

2020/07/18 09:30:54 Get "https://xxx.com/docs/swagger.json": dial tcp 35.190.71.25:443: i/o timeout

[GET /accounts GET /consents GET /payments GET /users DELETE /users PUT /accounts GET /delete-users GET /identity POST /payments POST /bulk-payment-auth-requests DELETE /consents GET /institutions POST /account-auth-requests PUT /account-auth-requests PATCH /account-auth-requests POST /payment-sortcode POST /payment-sortcode-auth-requests POST /users POST /bulk-payments POST /revoke-tokens POST /consent-auth-code POST /delete-users GET /features GET /jwks GET /me POST /pre-auth-requests GET /categories POST /consent-one-time-token POST /oauth PUT /payment-auth-requests POST /payment-auth-requests]

http: 2020/07/18 09:30:54 Server is ready to handle requests for mgmt API at :5001

http: 2020/07/18 09:30:54 Starting http server to serve metrics at port  :5002

http: 2020/07/18 09:30:54 Server is ready to handle requests from NGIX at :5000

2020/07/18 09:30:54 Verbose on
```

Let's check what happens while contacting nginx:

```
curl  localhost

<html>

<head><title>403 Forbidden</title></head>

<body>

<center><h1>403 Forbidden</h1></center>

<hr><center>nginx/1.19.1</center>

</body>

</html>
```

This is the mock api service:

```
curl localhost:8080/accounts

Welcome to the Test API server% 
```

Apifx will show on the logs the denied request:

```
2020/07/18 09:33:03 Request from: 172.17.0.1, uri: GET /

2020/07/18 09:33:03 Replied 403
```

Let's now use the management api to allow requests to the mock api:

```
curl -i localhost:5001/open

HTTP/1.1 200 OK 

```

the log will show the status

```
2020/07/18 09:35:06 open is true

```

A call to the Api endpoint will be successful now

```
curl -i localhost/accounts

HTTP/1.1 200 OK
```

Let's close again the gates and allow a single ip

```
curl -i localhost:5001/open

HTTP/1.1 200 OK 

curl -i "localhost:5001/addgoodip?ip=172.17.0.1"

HTTP/1.1 200 OK

Date: Sat, 18 Jul 2020 09:36:01 GMT
```

Apifx will show this entry:

```
2020/07/18 09:36:01 172.17.0.1 added
```


The api is accessible from this ip:


```
curl -i localhost/accounts

HTTP/1.1 200 OK
```

Let's also run a battery of test to the same  url

```
ab -n 1000 -k -q  localhost/accounts

Time taken for tests:   5.663 seconds

Complete requests:      1000

Failed requests:        0
```

For the next test, let's remove the ip:

```
curl -i "localhost:5001/delip?ip=172.17.0.1" 

HTTP/1.1 200 OK
```

which is confirmed by the apifx log entry:

```
2020/07/18 10:31:50 172.17.0.1 removed
```

we add now the same IP back with a rate limit per second:

```
curl -i "localhost:5001/addlimitip?ip=172.17.0.1,50"

HTTP/1.1 200 OK
```

the logs shows:

```
2020/07/18 10:32:50 172.17.0.1 added with rate limit of 50

2020/07/18 10:32:50 setting limit of 50 for 172.17.0.1
```

Now the simple load test will take much longer:

```
ab -n 1000 -k -q  localhost/accounts

Concurrency Level:      1

Time taken for tests:   19.963 seconds

Complete requests:      1000

Failed requests:        0
```

1000 requests limited by 50 per second took 20 second

```
ab -n 1000 -c 10 -k -q  localhost/accounts      

Concurrency Level:      10

Time taken for tests:   3.193 seconds

Complete requests:      1000
```

finally we have all prometheus stats:

```
curl localhost:5002/metrics               

# HELP access_total Total amount of requests checked

# TYPE access_total counter

access_total{access="/"} 1

access_total{access="/accounts"} 5260

access_total{access="172.17.0.1"} 5261

access_total{access="GET"} 5261

access_total{access="total"} 5261
```
