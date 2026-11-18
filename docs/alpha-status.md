# Alpha status

The engine API and enzUI adapter use the published enzUI alpha and pinned public
foundation forks. Native rendering requires a separately supplied WPE engine;
the mock backend never silently substitutes for a requested native backend.

All hosts use the engine selected by `runtime/engine.json`. Engine source lives
in the `enzim-webkit` fork. Native dependency recipes and prebuilt runtime
production belong to `enzim-webkit-flatpak`. Application builds compile Rust and
the credential guard without rebuilding WebKit or training PGO.

Shared Flatpak deployment supports application identity registration and verified
nested renderer isolation. A configured Flatpak host still requires the guard,
trusted renderer identity, separate mount/PID/network namespaces, seccomp and
no-new-privileges. Unregistered or unverifiable hosts fail closed.

HTTP/3 remains experimental. Media support depends on runtime codecs. Live media,
AT-SPI accessibility and GPU integration require their documented environments
and explicit qualification; compiling a feature is not a live test. Application
chrome, permission UI, persistence and final application packaging belong to the
host. Other CPU/architecture targets need separate native runtime qualification.

Host loopback filtering can affect transport fixtures and local traffic. Use
disposable profiles and an appropriate test network. The release checks do not
qualify every host firewall configuration.
