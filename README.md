# CSP Auditor [![Build Status](https://travis-ci.org/GoSecure/csp-auditor.png)](https://travis-ci.org/GoSecure/csp-auditor)

This plugin provided a readable view of CSP headers in Response Tab. It also include Passive scan rules to detect weak CSP configuration.

This project is package as a ZAP and Burp plugin.


## Download

Last updated : June 27th 2016

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
