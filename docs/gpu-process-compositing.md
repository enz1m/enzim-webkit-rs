# GPU process compositing

The optional WPE runtime features `UseGPUProcessForWebGL` and
`UseGPUProcessForCompositing` move WebGL or page painting/compositing into WebKit's
GPU process. Both are off by default in the Rust integration.

## Select before creating sessions

Call these on the native owner thread before creating the sessions they should
apply to:

```rust
use enzui_webkit::ffi::runtime::{
    set_gpu_process_for_compositing, set_gpu_process_for_webgl,
};

set_gpu_process_for_webgl(true);
set_gpu_process_for_compositing(true);
```

A web process retains the mode of its first page. Changing these requests does
not migrate existing pages. The setters record requests; session construction
returns `SessionError::GpuProcessUnsupported` if the runtime cannot enable a
requested feature. Use a matching reviewed source runtime and keep the GPU process
sandbox enabled.

## Native process and host responsibilities

With the compositing feature enabled, the web process records page/layer updates
and the GPU process paints and composites them. The patched runtime shares page
buffers through DMA-BUFs. Image/font handling and supported layer formats depend
on the selected native runtime.

The host still owns frame consumption, input, viewport changes and presentation
acknowledgments. GPU-process compositing does not replace the enzUI Vulkan import
path, grant permissions or relax destination policy. Keep exported frame leases
alive until GPU reads finish. Continue native dispatch while outstanding frame
completions retire after a page closes.

The adapter uses implicit DMA-BUF synchronization. Explicit synchronization-file
import is not implemented, and software rendering uses the CPU fallback. These
are separate capabilities from WebKit's internal GPU-process feature.

See the [engine guide](../crates/enzui-webkit/README.md#frame-delivery-and-ownership)
for frame ownership and the [native runtime guide](native-runtime.md) for
runtime source identities and licenses.
