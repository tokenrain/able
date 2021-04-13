# able

Able is a utility designed to help in the proving out of or migration to
a microservices orchestrated environment.

In a microservices environment you have many small applications exposing
a variety of protocols that connect to each other in a variety of ways.
Moving to microservices often means using brand new infratructure tools
around deployment, metrics, monitoring and logging.  The truly
adventurous employ a service mesh with mutual TLS, service discovery,
and advanced load balacing, rate limitimg, and circuit breaking
capabilities.

Able is designed as a test application that is "able" to do many things
in helping your validate your new computing paradigm.

## Multiple transports

Able has support for five transports:
- http
- https
- tcp
- tcps (tcp + tls)
- grpc (tls)

Able will setup a listener on a discrete port for each transport. This
is a very simple echo server.

For http and https able will echo back the url you query it with.

For tcp and tcps able will echo back every newline terminated string
that you send over the connection.

For grpc the DoEcho service sends a Reply of the same content for each
Request.

## Memory and CPU consumption

Moving away from bare metal or virtual servers to a cgroup based
resource allocation model can change the way that one monitors and
alerts on high memory and high CPU situations. With an OOM killer in
play it can be useful to see how your environment alerts on this type of
interruption.

Able, via the admin interface, allows you to grow/shrink its resident
memory size dymaically using the unit of MB (megabytes)

Able, via the admin interface, allows you to "max out" a number of
(v)cpus dynamically.

## Receiver Latency and Error Rates

A lot of application monitoring and alerting is based on request latency
and error rates. Able allows you to create both artificial latency and
error rates.

On the latency side you can tell able for each tansport to add some
number of ms latency to each repsonse. This can be dynamiclly controlled
via the admin interface.

On the error rate side you can tell able for each tansport to create a
error response for some percentage of requests. This can be dynamiclly
controlled via the admin interface.

## Sender Latency and Send Rates

Able can act as a sender as a way to generate load on the receiver to
test out various capacity paramaters.

By default for each transport there is one sender worker making a
request every 250 milliseconds.

The number of simultaneos workers that are sending requests to a single
transport is the send_rate.

The amount of time each send worker waits between sending requests is
the latency.

These are tunable dynamically via the admin interface.

## Logging

Able can log to stdout or to a set of files in a specified
directory. Log format is either unstructured (line) or structured (json)

## Metrics

The admin endpoint exposes a `/metrics` route which exposes Prometheus
metrics. The number of requests, a histogram of their latency, and the
number of errors is exposed for both the receiver and the sender.

## Health Status

Often it is useful to know with an orchestrator what will happen when
your app enters an unhealthy state or never reaches a healthy state.

Via the `sick_file` configuration paramater you can tell able not to
reach a healty statye upon startup.

Via the admin interface you can set the result of the /health enpoint of
the admin listenter to healthy(200) or unhealthy(500).

## Dead Status

Often it is useful to know with an orchestrator what will happen when
your app will not even start.

Via the `dead_file` configuration paramater you can tell able not to
reach a running state but die when it attemps to run.

## Admin Interface

Both able receivers and senders setup an admin https server that is used
(1) as the canonical health endpoint and (2) metrics exposition and (3)
the interface to get/set all of the tunables. The entire REST API is shown
under the **Admin Interface Routes** section.

## Configuration

The easiest way to configure able is via a yaml based configuration
file. See `conf/config.yml` for all of the ways that able can be
configured. All configuration directives can be set through environment
variables.

## Admin Interface Routes

```
curl -X GET https://admin:port/health

curl -X PUT https://admin:port/health?healthy={true,false}

----------------

curl -X GET https://admin:port/metrics

----------------

curl -X GET https://admin:port/admin/resource
curl -X GET https://admin:port/admin/resource/{memory,cpu}

curl -X PUT https://admin:port/admin/resource/memory?value=int # the number of MB to consume
curl -X PUT https://admin:port/admin/resource/cpu?value=int    # the number of cpus to consume

----------------

curl -X GET https://admin:port/receiver/{error,latency}
curl -X GET https://admin:port/receiver/{error,latency}/{http,https,tcp,tcps,grpc}

curl -X PUT https://admin:port/receiver/error/{http,https,tcp,tcps,grpc}?value=int   # the percentage (0-99) of requests should error
curl -X PUT https://admin:port/receiver/latency/{http,https,tcp,tcps,grpc}?value=int # the number of ms to add to each request

----------------

curl -X GET https://admin:port/sender/{rate,latency}
curl -X GET https://admin:port/sender/{rate,latency}/{http,https,tcp,tcps,grpc}

curl -X PUT https://admin:port/sender/rate/{http,https,tcp,tcps,grpc}?value=int    # the number of workers sending requests simultaneously
curl -X PUT https://admin:port/sender/latency/{http,https,tcp,tcps,grpc}?value=int # the number of ms each worker waits between requests
```
