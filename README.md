
# swurl
A python tool intended to provide very basic functionality similar to `curl`, allowing you to make signed HTTP requests to AWS service endpoints over `socks5`.  
  
  
   
## Requirements
- awscli configured locally
- python3 and `botocore` pip module
- SSH access to EC2 instance in same VPC with port forwarding ability  
   
  
## Info

This tool only exists so I could provide a way to communicate with an endpoint in a private VPC over SOCKS proxy. It started as a simple request to help access a DB instance and soon turned into both a learning exercise and guide. I've documented it below in case others find it useful or helpful.
  
**NOTE:** There are other tools out there that already provide `curl`-like functionality that are probably better managed and supported. 

**Some thoughts after working on this:**
- It would be cool if there was consistency between service names and service endpoints. This would allow us to easily derive both the `region` and `service`  from the endpoint itself. For example, the service name required when signing requests for AWS for Neptune is `neptune-db` but all cluster and instance endpoints are in format: `{identifier}.{region}.{neptune}.amazonaws.com`
- `botocore` should allow something other than `HTTPS_PROXY` as an option to provide proxy config. Maybe a unique environment variable such as `AWS_PROXY` or a configuration option. Not saying they should ignore the standard env var but what if I only want to proxy `botocore` functions without affecting other applications?
- `socks5` is awesome. Dynamic port forwarding over SSH in general is a powerful tool for accessing AWS resources and services if you don't have a VPN. With a single `ssh` command I have access to my VPC and multiple services which are not publicly exposed e.g. `neptune` and `es`. This can be combined with AWS SSM to achieve access without exposing any public resources.  
   
   
## Accessing private resources inside a VPC
So, you've launched a new AWS Neptune cluster and now need to query it remotely via the rest API. A few things worth noting:

- Neptune must be provisioned inside a VPC
- It will only respond to local requests from within the VPC
- Neptune does not expose any public cluster or instance endpoints
- All connections must be over TLS (enforced in `ap-southeast-2`)
- Username/password auth is not an option for neptune so IAM authentication it is  
  
    
## General strategies to provide access    
- Expose a public NLB that terminates SSL and proxies requests to the cluster endpoint
- Expose a public ALB that forwards requests to `haproxy`  running on EC2, which then proxies requests to Neptune
- Setup API gateway and expose an endpoint. This triggers a lambda function with permission to query neptune and return the results. Could be set up to accept either IAM for auth or a custom lambda authoriser
- dedicated VPN to the VPC

See some samples from AWS -> https://github.com/aws-samples/aws-dbs-refarch-graph/tree/master/src/connecting-using-a-load-balancer  
    
   
## Access using SSH (and SSM?)

Here we will go over some of the ways you can use SSH to access private resources in your VPC.  

The most common way is via a public-facing bastion you have access to:
```
                              +--------------------------------------------+
                              | +-----------------+            VPC         |
+----------------+            | |  public subnet  |   +-----------------+  |
|  laptop/pc     |            | |  +-----------+  |   |  private subnet |  |
|                |            | |  |           |  |   |   +----------+  |  |
| +-------+     +-------------------+          |<-------->|  neptune |  |  |
| |  app  |<--->|   SSH tunnel      | instance |  |   |   +----------+  |  |
| +-------+     +-------------------+  (EC2)   |  |   |    +--------+   |  |
|                |            | |  |           |<--------->|   ES   |   |  |
|                |            | |  +-----------+  |   |    +--------+   |  |
+----------------+            | +-----------------+   +-----------------+  |
                              +--------------------------------------------+
```
  
  
But, by making use of AWS SSM we can access our neptune cluster without exposing any public resources. Like below:
```
                                 +---------------------------------+
+----------------+               |      PRIVATE SUBNET IN VPC      |
|  laptop/pc     |               | +-----------+                   |
|                |               | |           |      +----------+ |
| +--------+    +-------------------+          |<---->|  neptune | |
| |  app   |<-->|    SSH tunnel     | instance |      +----------+ |
| +--------+    +-------------------+  (EC2)   |      +--------+   |
|                |               | |           |<---->|   ES   |   |
+----------------+               | +-----------+      +--------+   |
                                 +---------------------------------+
```

For more information on SSH and SSM, see the official documentation here -> https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-getting-started-enable-ssh-connections.html

I won't be going over how to set up SSM in this guide but continue reading for details on SSH.  
  
    
## How to forward all the ports using SSH  
  
### Local port forwarding

One  way of achieving this is to setup local port forwarding via SSH.  For example:
```
$ ssh -f -NT user@bastion.host.com -L 8182:name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182
```
This tells SSH to bind to local port `8182` and forward all TCP traffic to the neptune endpoint on port `8182`  via the  `bastion`.  This can be used to securely access unencrypted services (e.g. `HTTP` or `SMTP`) by using SSH to encrypt communication between your machine and the remote server.
  
In our case we are required to communicate with `neptune` via TLS. One of the challenges for developers and/or others accessing these endpoints is that local applications might complain about the SSL certificate (provided by the endpoint) not matching the hostname we're connecting to:
```
$ curl https://localhost:8182/status -H 'Host: name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182'
curl: (60) SSL: no alternative certificate subject name matches target host name 'localhost'
More details here: https://curl.haxx.se/docs/sslcerts.html
```
From `curl`'s verbose output:
```
*   Trying ::1:8182...
* TCP_NODELAY set
* Connected to localhost (::1) port 8182 (#0)
* ALPN, offering h2
* ALPN, offering http/1.1
* successfully set certificate verify locations:
*   CAfile: /etc/pki/tls/certs/ca-bundle.crt
  CApath: none
* TLSv1.3 (OUT), TLS handshake, Client hello (1):
* TLSv1.3 (IN), TLS handshake, Server hello (2):
* TLSv1.2 (IN), TLS handshake, Certificate (11):
* TLSv1.2 (IN), TLS handshake, Server key exchange (12):
* TLSv1.2 (IN), TLS handshake, Server finished (14):
* TLSv1.2 (OUT), TLS handshake, Client key exchange (16):
* TLSv1.2 (OUT), TLS change cipher, Change cipher spec (1):
* TLSv1.2 (OUT), TLS handshake, Finished (20):
* TLSv1.2 (IN), TLS handshake, Finished (20):
* SSL connection using TLSv1.2 / ECDHE-RSA-AES128-GCM-SHA256
* ALPN, server did not agree to a protocol
* Server certificate:
*  subject: CN=*.identifier.ap-southeast-2.neptune.amazonaws.com
*  start date: Jan 15 00:00:00 2020 GMT
*  expire date: Feb 15 12:00:00 2021 GMT
*  subjectAltName does not match localhost
* SSL: no alternative certificate subject name matches target host name 'localhost'
* Closing connection 0
* TLSv1.2 (OUT), TLS alert, close notify (256):
curl: (60) SSL: no alternative certificate subject name matches target host name 'localhost'
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```
So, a quick google search tells us we can "fix" this using the `--insecure` option (and now we're getting output!):
```
$ curl -k https://localhost:8182/status -H 'Host: name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182'
{"requestId":"494c6472-b1b5-42ce-80d0-d7d2a46266cd","code":"AccessDeniedException","detailedMessage":"Missing Authentication Token"}
```
**NOTE**:  This is not a solution and will not always work. Applications are not required to have functionality allowing you to ignore or bypass SSL hostname verification. Consider having `ssh` bind to a local port on something like `127.0.1.10` and using your `hosts` file if you need to make this work.

It's still annoying though having to manually specify the `host` header every time we make a request. We also potentially need to implement alternate logic in our code to account for when we use local port forwarding..  
  
  
### Dynamic port forwarding (SOCKS)  

As I've come to discover, most if not all AWS services support dynamic port forwarding over SOCKS. This means we can tell `ssh` to bind to a local port and act as a SOCKS proxy server. When we connect to the local port the request is forwarded over the secure tunnel to the bastion and then to the relevant endpoint based on the application protocol (determined by the `hostname` and `port` in our request). We can now send HTTPS requests without having to worry about specifying the `host` header each time!
  
Example of setting up dynamic forwarding on local port `8888`:
```
$ ssh -f -NT -D 8888 user@bastion.host.com
```
We've told `ssh` to go to the background with `-f` and can use `ss` to verify `ssh` is listening on port `8888`:
```
$ ss -lntp sport :8888
State     Recv-Q    Send-Q       Local Address:Port         Peer Address:Port    Process                             
LISTEN    0         128              127.0.0.1:8888              0.0.0.0:*        users:(("ssh",pid=544833,fd=8))    
LISTEN    0         128                  [::1]:8888                 [::]:*        users:(("ssh",pid=544833,fd=5)) 
```

So now we can query the cluster endpoint by specifying the `socks5` proxy with `curl`:
```
$ curl -x socks5://localhost:8888 https://name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182/status
curl: (6) Could not resolve host: name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com
```
Well. That's annoying.. DNS for the cluster endpoints resolve to private IP addresses:
```
$ dig name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com @1.1.1.1 +short
instance20200521052459345800000002.identifier.ap-southeast-2.neptune.amazonaws.com.
10.0.40.33
```
     
    
### Using socks5h  
  
A solution to our problem, implemented by `libcurl`, is `socks5h` (`CURLPROXY_SOCKS5_HOSTNAME`) [0]. The difference between this and regular `socks5` is that we tell the SSH proxy to take care of DNS resolution (in our case, via the bastion). Now we can query the endpoint directly even though we can't resolve DNS locally:
```
$ curl -x socks5h://localhost:8888 https://name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182/status
{"requestId":"494c6472-b1b5-42ce-80d0-d7d2a46266cd","code":"AccessDeniedException","detailedMessage":"Missing Authentication Token"}
```
FYI the python `requests` library supports the `socks5h` implementation. Many applications make use of `libcurl` and hopefully more libraries will support the `hostname` implementation of `socks5` in future.
[0] https://curl.haxx.se/libcurl/c/CURLOPT_SOCKS_PROXY.html  
  
  
## IAM Authentication  

And now, the last piece of the puzzle.. how do we authenticate using our IAM credentials when making HTTP `GET` or `POST` requests?

Basically, we need to sign our request by attaching authentication information in the `headers` of our HTTP request. This signature is calculated and created using information from our http request along with our AWS `credentials`, the `service` we're querying and the `region` the service is in. 

See here for more information -> https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

After trying out a couple of tools I ran into some issues when specifying non-standard URLs e.g. while using  port forwarding with custom `host` headers. Being able to specify a `socks5h` proxy was also a requirement in my case. I ended up putting together `swurl` which makes use of `botocore`'s signing functions.
  
    
## Usage examples  

Query `GetCallerIdentity` using `GET` request to AWS STS endpoint:
```
[elpy@testbox ~]$ swurl --profile sandpit --service sts --region us-east-1 'https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15'
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/elpy-admin/botocore-session-1590482957</Arn>
    <UserId>AROAUBLYXXXXXXACIWXS2:botocore-session-1590482957</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>26374e3f-9b12-4526-8649-d19eaf366e02</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
```

Query `GetUser` using `GET` request to IAM endpoint:
```
[elpy@testbox ~]$ swurl --profile sandpit --service iam --region us-east-1 'https://iam.amazonaws.com/?Action=GetUser&UserName=elpy&Version=2010-05-08'
<GetUserResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <GetUserResult>
    <User>
      <Path>/</Path>
      <Arn>arn:aws:iam::0123456789012:user/elpy</Arn>
      <UserName>elpy</UserName>
      <UserId>AIDAUBXXXXXX47Z2RDQSM</UserId>
      <CreateDate>2020-04-27T11:27:42Z</CreateDate>
    </User>
  </GetUserResult>
  <ResponseMetadata>
    <RequestId>69790a00-0484-49b0-b04f-ff466594807b</RequestId>
  </ResponseMetadata>
</GetUserResponse>
```
Querying our `neptune` cluster via the `socks5h` proxy:
```
[elpy@testbox ~]$ swurl --socks localhost:8888 --profile sandpit --service neptune-db --region ap-southeast-2 https://name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182/status
{"status":"healthy","startTime":"Thu May 21 05:30:27 UTC 2020","dbEngineVersion":"1.0.2.2.R2","role":"writer","gremlin":{"version":"tinkerpop-3.4.3"},"sparql":{"version":"sparql-1.1"},"labMode":{"ObjectIndex":"disabled","ReadWriteConflictDetection":"enabled"}}
```

Use the `--env` option to print out the required environment variables so we don't need to keep specifying cli arguments:
```
$ swurl --socks localhost:8888 --profile sandpit --service neptune-db --region ap-southeast-2 https://name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182/status --env
export AWS_PROFILE="sandpit"
export AWS_SERVICE="neptune-db"
export AWS_REGION="ap-southeast-2"
export SWURL_SOCKS="localhost:8888"
```

Copy and paste them in, and you can continue without all the arguments:
```
[elpy@testbox ~]$ export AWS_PROFILE="sandpit"
[elpy@testbox ~]$ export AWS_SERVICE="neptune-db"
[elpy@testbox ~]$ export AWS_REGION="ap-southeast-2"
[elpy@testbox ~]$ export SWURL_SOCKS="localhost:8888"
[elpy@testbox ~]$ swurl https://name.cluster-identifier.ap-southeast-2.neptune.amazonaws.com:8182/gremlin/status
{
    "acceptedQueryCount" : 0,
    "runningQueryCount" : 0,
    "queries" : [ ]
}
```
Querying a non-public elasticsearch cluster:
```
[elpy@testbox ~]$ swurl --profile sandpit --socks localhost:8888 --region ap-southeast-2 --service es 'https://elpydev-identifier.ap-southeast-2.es.amazonaws.com/_cluster/health?wait_for_status=yellow&timeout=50s&pretty'
{
  "cluster_name" : "824439210008:elpydev",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 1,
  "number_of_data_nodes" : 1,
  "discovered_master" : true,
  "active_primary_shards" : 1,
  "active_shards" : 1,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 0,
  "delayed_unassigned_shards" : 0,
  "number_of_pending_tasks" : 0,
  "number_of_in_flight_fetch" : 0,
  "task_max_waiting_in_queue_millis" : 0,
  "active_shards_percent_as_number" : 100.0
}
```
Make a `POST` request to IAM service to create new group:
```
[elpy@testbox ~]$ swurl --profile sandpit -X POST -d 'Action=CreateGroup&GroupName=Testing111&Version=2010-05-08' --service iam --region us-east-1 'https://iam.amazonaws.com/'
<CreateGroupResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <CreateGroupResult>
    <Group>
      <Path>/</Path>
      <GroupName>Testing111</GroupName>
      <GroupId>AGPAUXXXXJQSRHH7KYEP4</GroupId>
      <Arn>arn:aws:iam::012345678901:group/Testing111</Arn>
      <CreateDate>2020-05-27T13:24:48Z</CreateDate>
    </Group>
  </CreateGroupResult>
  <ResponseMetadata>
    <RequestId>71f717e8-7d3c-4818-a2c5-4abd2f7991f2</RequestId>
  </ResponseMetadata>
</CreateGroupResponse>

```

