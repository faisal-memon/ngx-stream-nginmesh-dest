# NGINX Destination IP recovery module for stream

This dynamic module recovers original IP address and port number of the destination packet.
It is used by nginmesh sidecar where all outgoing traffic is redirect to a single port using iptable mechanism

## Dependencies

This module uses Linux **getsockopt** socket API.  
The installation uses Docker to build the module binary.

## Compatibility

* 1.11.x (last tested with 1.13.5)


## Synopsis

```nginx

stream   {
    server {
        #  use iptable to capture all outgoing traffic.  see Istio design document
        listen 15001;
			
        # turn on module for this server
        # original IP destination and port is set to variables
        # $server_orig_addr and $server_orig_port respectively
        use_orig_dst on;
	
        # variable can be used in valid config directive
        proxy_pass $server_orig_addr:$server_orig_port;
    }
		
 }	

```

## Embedded Variables

The following embedded variables are provided:

* **server_orig_addr**
  * Original IP address
* **server_orig_port**
  * Original port

## Directives

### use_orig_dst

| -   | - |
| --- | --- |
| **Syntax**  | **use_orig_dst** \<on\|off\> |
| **Default** | off |
| **Context** | stream, server |

`Description:` Enables or disables the use_orig_dst module


## Installation

1. Clone the git repository

2. Build the Docker container with the dynamic module

  ```
  shell> docker build -t orig_dst .
  ```

3. Run the Docker container

  ```
  shell> docker run --name orig_dst --cap-add=NET_ADMIN -d -p 80:80 orig_dst
  ```

4. Shell into the container to setup iptables rules

  ```
  shell> docker run --name orig_dst --cap-add=NET_ADMIN -d -p 80:80 orig_dst
  ```

5. Redirect all outbound traffic to port 15501

  ```
  shell> iptables -t nat -N NGINX_REDIRECT && \
         iptables -t nat -A NGINX_REDIRECT -p tcp -j REDIRECT --to-port 15501 && \
         iptables -t nat -N NGINX_OUTPUT && \
         iptables -t nat -A OUTPUT -p tcp -j NGINX_OUTPUT && \
         iptables -t nat -A NGINX_OUTPUT -j NGINX_REDIRECT
  ```

6. Redirect all inbound traffic to port 15501

  ```
  shell> iptables -t nat -N NGINX_IN_REDIRECT && \
         iptables -t nat -A NGINX_IN_REDIRECT -p tcp -j REDIRECT --to-port 15501 && \
         iptables -t nat -N NGINX_INBOUND && \
         iptables -t nat -A PREROUTING -p tcp -j NGINX_INBOUND && \
         iptables -t nat -A NGINX_INBOUND -p tcp -j NGINX_IN_REDIRECT
  ```

7. Curl port 80 on localhost, it should return the original ip address and port

  ```
  shell> curl http://localhost:80
         172.17.0.2:80
  ```
  
## Integration test

Note: Not sure this still works

This works only on mac.

```bash
make test-nginx-only
make test-tcp
```
