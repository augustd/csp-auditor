# CSP Auditor [![Build Status](https://travis-ci.org/GoSecure/csp-auditor.png)](https://travis-ci.org/GoSecure/csp-auditor)

This plugin provides:

* a readable view of CSP Headers in Response Tab
* passive scan rules to detect weak CSP configuration
* a CSP configuration generator based on the Burp crawler or using manual browsing

This project is packaged as a ZAP and Burp plugin.

## Download

Last updated : July 20th 2017

 - [Burp plugin](https://github.com/GoSecure/csp-auditor/blob/master/downloads/csp-auditor-burp-1.jar?raw=true)
 - [ZAP plugin](https://github.com/GoSecure/csp-auditor/blob/master/downloads/cspauditor-alpha-1.zap?raw=true)

## Screenshots

![CSP Auditor Burp Plugin](https://raw.githubusercontent.com/GoSecure/csp-auditor/master/demo.gif)

## Building the plugin

Type the following command:

```
./gradlew build
```

or if you have already Gradle installed on your machine: 

```
gradle build
```

## Read more

For more context around Content-Security-Policy and how to apply it to your website see our blog posts on the topic:

* http://gosecure.net/2017/07/20/building-a-content-security-policy-configuration-with-csp-auditor
* https://gosecure.net/2016/06/28/auditing-csp-headers-with-burp-and-zap/
