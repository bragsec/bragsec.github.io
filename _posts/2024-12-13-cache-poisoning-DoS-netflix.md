---
title: CP-DoS on Netflix:
date: 2024-12-13 12:00:00 -500
categories: [bugbounty]
tags: [bugbounty]
---

## CP-DoS: 
[**CP-DoS (Cache Poisoning Denial of Service)**](https://cpdos.org/) is a type of web application attack where an attacker exploits vulnerabilities in caching mechanisms to poison the cache with malicious or incorrect responses. The goal is to disrupt the normal functionality of a web application or degrade its performance, often causing denial of service (DoS) for legitimate users. Read more about cache poisoning techniques here:
- [`Practical Web Cache Poisoning - James Kettle`](https://portswigger.net/research/practical-web-cache-poisoning) 
- [`Bypassing Web Cache Poisoning Countermeasures - James Kettle`](https://portswigger.net/research/bypassing-web-cache-poisoning-countermeasures) 
- [`Web Cache Entanglement: Novel Pathways to Poisoning - James Kettle`](https://portswigger.net/research/web-cache-entanglement) 
- [`Responsible denial of service with web cache poisoning - James Kettle`](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning) 
- [`The Case of the Missing Cache Keys - @enumerated`](https://enumerated.wordpress.com/2020/08/05/the-case-of-the-missing-cache-keys/) 
- [`Cache Poisoning at Scale - @youstin`](https://youst.in/posts/cache-poisoning-at-scale/) 
- [`Caching the Un-cacheables - Abusing URL Parser Confusions (Web Cache Poisoning Technique) - @nokline`](https://nokline.github.io/bugbounty/2022/09/02/Glassdoor-Cache-Poisoning.html) 
- [`Abusing HTTP Path Normalization and Cache Poisoning to steal Rocket League accounts - @samcurry`](https://samcurry.net/abusing-http-path-normalization-and-cache-poisoning-to-steal-rocket-league-accounts) 
- [`Gotta cache 'em all: bending the rules of web cache exploitation - @tincho_508`](https://portswigger.net/research/gotta-cache-em-all) 

## CP-DoS (Disagreement of RFC 3986 5.2.4): 
According to the [**RFC 3986 Section 5.2.4**](https://datatracker.ietf.org/doc/html/rfc3986), this section outlines the standard behavior for path normalization in URLs, including how "dot segments" should be handled. The disagreement here is that the cache server and origin server are not adhering to the same normalization rules, creating an inconsistency which allows an attacker to create cache keys resulting in a different response leading to DoS.

## CP-DoS on Netflix: 
When hunting on Netflix, I realized that the cache server was doing path normalization by decoding "dot segments" before generating the cache key. While the origin server was not doing any sort of normalization. (**Disagreement of RFC 3986 5.2.4**).

Which means both "`/en/home`" and "`/en/../home`" were hitting the same cache key for the cached response but returned different responses.

For example:
- "`/en/home`" returns **200 OK**,
but,
- "`/en/../home`" returns **404 Not Found**.

So, it was possible to trick the cache server into caching **404** pages replacing genuine ones.

## Steps To Reproduce:
1. Navigate to `https://redacted.netflix.com/en`
2. Open BurpSuite and Capture any request. For e.g: `/en/fr_fr` (French page)
3. Add a cache buster to not harm genuine users `?cb=hackingsucks`. 
4. Send the poisoned (dot segmented) request like this:
```
GET /en/xxx/../fr_fr/?cb=hackingsucks HTTP/2
Host: redacted.netflix.com
User-Agent: Chrome/131.0.0.0 Safari/537.36

```
5. Resend the request without the dot segment and it should return a `404 Not Found` page.
6. Try loading the content with a different browser or incognito mode, it should be gone.

## Impact: 
This issue leads to persistence denial of service attack for all resources hosted on `redacted.netflix.com`.

## Timeline:
- December 7, 2024, 1:59pm - Report sent to Netflix
- December 8, 2024, 6:42pm - First Response from the Triage team
- December 10, 2024, 5:18pm - Triaged and paid (**$600**) 
- December 10, 2024, 5:20pm - Issue Resolved

Happy Hacking,
@nischalxd