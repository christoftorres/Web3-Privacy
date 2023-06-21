# request-logger

## Run logger over multiple sites

Before running the logger over multiple sites, open run-multiple.sh and
correctly set its environment variables.  Once that's done, run:

```
./run-multiple.sh PATH_TO_SITES
```

The variable `PATH_TO_SITES` must point to a file that contains URLs, one per
line.  If you want to run the logger with MetaMask enabled, you first have to
install it in the Chrome profile.  To do so, open the logger for a few minutes
on a dummy site, and go through MetaMask's onboarding process:

```
./run.js \
    --interactive \
    --binary /opt/google/chrome/google-chrome \
    --profile /path/to/chrome/profile \
    --secs 300 \
    --url 'https://dummy.com'
```

## Run logger over a single site

```
usage: run.js [-h] -b BINARY [--debug {none,debug,verbose}] -u URL
              [-p PROFILE] [-a] [--interactive] [-t SECS]

CLI tool for recording requests made when visiting a URL.

optional arguments:
  -h, --help            show this help message and exit
  -b BINARY, --binary BINARY
                        Path to a puppeteer compatible browser.
  --debug {none,debug,verbose}
                        Print debugging information. Default: none.
  -u URL, --url URL     The URL to record requests no
  -p PROFILE, --profile PROFILE
                        Path to use and store profile data to.
  -a, --ancestors       Log each requests frame hierarchy, not just the
                        immediate parent. (frame URLs are recorded from
                        immediate frame to top most frame)
  --interactive         Show the browser when recording (by default runs
                        headless).
  -t SECS, --secs SECS  The dwell time in seconds. Defaults: 30 sec.
```
