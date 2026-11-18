# Media playback runtime

Playback uses the GStreamer libraries, codecs and plugin configuration supplied
by the native engine distribution. Rust applications do not build GStreamer.

The qualified engine uses a private GStreamer 1.28.5 playback plugin. Its patch
preserves request-pad numbering while pads survive READY to NULL. Resetting the
counter with live pads can reuse names and abort audio/video reconfiguration.
The native packaging project, `enzim-webkit-flatpak`, owns the source pin,
dependency patch, build receipt, license and regression fixture.

For Flatpak, the shared Platform installs the qualified plugin under its native
prefix. For a prepared native runtime, the verified launcher overlays only that
plugin's system location through a read-only namespace binding. The host's
installation is not modified. The runtime manifest must match the playback
selection in [`runtime/engine.json`](../runtime/engine.json); missing or changed
plugin material causes verification failure.

Codec availability, hardware decoding and audio output depend on the actual
runtime and host environment. A successful software video test does not qualify
all codecs or hardware paths. Hosts still own media permissions and user controls.
See [native runtime setup](native-runtime.md) for the engine/build split.
