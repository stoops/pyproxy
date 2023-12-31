# pyproxy

## Test

```
cmdl = ["/bin/echo", "-n", "8.8.8.8:53"]
```

## Nix

```
#!/bin/bash
addr="$1"
port="$2"
prot="$3"
if [ "$addr" != "" -a "$port" != "" ] ; then
  conn=$(conntrack -L 2>/dev/null | tr '\t' ' ' | grep -i " src=${addr} .* sport=${port} " | grep -i "${prot}" | tr ' ' '\n' | grep -Ei '^(dst|dport)=' | head -n 2 | tr '\n' '=' | awk -F '=' '{ print $2":"$4 }')
  echo -n "${conn}"
fi
exit 0
```

# Mac

```
vim /etc/defaults/periodic.conf
launchctl disable system/com.apple.tmp_cleaner
```
