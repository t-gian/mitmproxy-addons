# Mitmproxy Addons

A collection of useful Mitmproxy Addons that I developed for testing and playing around with the mitmproxy.

# Usage

Run `mitmproxy` with one or more addons:

```sh
$ mitmproxy \
    -s virusTotalChecker.py \
    -s advancedDoS.py
```

Or while running:

```
: set scripts=virusTotalChecker.py
```

Or via [config.yaml](https://docs.mitmproxy.org/stable/concepts-options/):


# Addons List

## [`virusTotalChecker.py`](./virusTotalChecker.py)

This addon checks through the VirusTotal [API](https://docs.virustotal.com/reference/overview) if a given URL set in the [filter](https://docs.mitmproxy.org/stable/concepts-filters/) option is malicious or not. If at least one security engine flags the URL as malicious the proxy will kill the request.
**Remember to insert your own API-key (an indication of where to insert it is given in the script)**

Options:

* `virus_total_filter` - check requests matching this filter. If the URL is flagged as malicious by VirusTotal kill the flow.

## [`advancedErrors.py`](./advancedErrors.py)

This addon allows to set an error_rate and a [filter](https://docs.mitmproxy.org/stable/concepts-filters/). All flows' responses that match the filter will return a random HTTP error response according to the probability set by the error_rate. In this case error_rate is the percentage of probability for which HTTP error responses are forged for the specific filtered flow.

For example, to replace any response from `google.com` with an HTTP error status code with probability equal to 50%:

```
: --set error_rate=50 --set error_filter="~u google.com"

```
The error code returned is randomly picked from this list of HTTP-known error codes = (400, 403, 404, 500, 502, 503, 504)

Options:

* `error_rate` - set probability of error response being generated
* `error_filter` - set the filtered flows to which apply the addon


## [`advancedDelay.py`](./advancedDelay.py)

This addon adds a delay before sending a request. Also here a filter can be specified. 

Options:

* `sleep` - delay client requests by this amount of time (seconds)
* `sleep_filter` - delay only flows which match the [filter](https://docs.mitmproxy.org/stable/concepts-filters/)

## [`advancedDoS.py`](./advancedDoS.py)

this addon simulates a scenarion in which the proxy is not available, like the proxy was hit by a DoS attack, by killing all (or matching a filter) requests.

Options:

* `DoS` - kill all flows
* `DoS_filter` - kill only flows matching the [filter](https://docs.mitmproxy.org/stable/concepts-filters/)

## [`killHTTP.py`](./killHTTP.py)

Simple addon that kills all HTTP flows.


## [`randomDelayHTTP.py`](./randomDelayHTTP.py)

Simple addon that delays all HTTP requests by a random delay. The delay will be randomly picked in a given range inserted by the user.

## [`randomErrorsHTTP.py`](./randomErrosHTTP.py)

Simple addon that given a rate_error probability value forges responses to HTTP flows as HTTP error code responses.

Basically, these last 3 addons were the initial version of some of the more advanced addons.
