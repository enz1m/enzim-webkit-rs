#!/usr/bin/env python3
"""Verify and launch a pinned prebuilt WebKit runtime with its native sandbox."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
LIBEXEC = "/usr/local/libexec/wpe-webkit-2.0"
DATADIR = "/usr/local/share/wpe-webkit-2.0"
INSPECTOR_RESOURCE = "share/wpe-webkit-2.0/inspector.gresource"
CHILDREN = ("WPEWebProcess", "WPENetworkProcess", "WPEGPUProcess")
FS_IOC_MEASURE_VERITY = 0xC0046686


def measure_verity_descriptor(descriptor):
    buffer = bytearray(struct.pack("=HH", 0, 64) + bytes(64))
    try:
        fcntl.ioctl(descriptor, FS_IOC_MEASURE_VERITY, buffer, True)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTTY, errno.EOPNOTSUPP, errno.EPERM):
            return None
        raise
    algorithm, size = struct.unpack_from("=HH", buffer)
    if algorithm != 1 or size != 32:
        raise ValueError("source runtime requires SHA-256 fs-verity digests")
    return {"algorithm": "sha256", "digest": buffer[4:36].hex()}


def measure_verity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return measure_verity_descriptor(descriptor)
    finally:
        os.close(descriptor)


def verify_file(path, expected):
    seal = expected.get("fsverity")
    if seal is not None:
        raw = expected.get("sha256")
        if (not isinstance(raw, str) or len(raw) != 64
                or any(c not in "0123456789abcdef" for c in raw)):
            raise ValueError("source runtime fs-verity record requires a portable SHA-256 identity")
        if (not isinstance(seal, dict) or set(seal) != {"algorithm", "digest"}
                or seal["algorithm"] != "sha256" or not isinstance(seal["digest"], str)
                or len(seal["digest"]) != 64 or any(c not in "0123456789abcdef" for c in seal["digest"])):
            raise ValueError("invalid source runtime fs-verity identity")
        measured = measure_verity(path)
        if measured is not None:
            if measured != seal:
                raise ValueError("source runtime fs-verity identity changed: " + str(path))
            if os.environ.get("ENZUI_WPE_FULL_RUNTIME_HASH") != "1":
                return
    if digest(path) != expected["sha256"]:
        raise ValueError("source runtime file changed: " + str(path))


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


WEBKIT_LICENSES = {
    "WebKit-LGPL-2": "Source/WebCore/LICENSE-LGPL-2",
    "WebKit-LGPL-2.1": "Source/WebCore/LICENSE-LGPL-2.1",
    "WebKit-BSD-Apple": "Source/WebCore/LICENSE-APPLE",
    "JavaScriptCore-LGPL-2": "Source/JavaScriptCore/COPYING.LIB",
    "WTF-LLVM": "Source/WTF/LICENSE-LLVM.txt",
    "WTF-libc++": "Source/WTF/LICENSE-libc++.txt",
    "WTF-simde": "Source/WTF/LICENSE-simde.txt",
    "WTF-zmij": "Source/WTF/LICENSE-zmij.txt",
    "WTF-ICU": "Source/WTF/icu/LICENSE",
    "ANGLE": "Source/ThirdParty/ANGLE/LICENSE",
    "Skia": "Source/ThirdParty/skia/LICENSE",
    "pdf.js": "Source/ThirdParty/pdfjs/LICENSE",
    "xdgmime": "Source/ThirdParty/xdgmime/README",
    "Inspector-CodeMirror": "Source/WebInspectorUI/UserInterface/External/CodeMirror/LICENSE",
    "Inspector-CSSDocumentation": "Source/WebInspectorUI/UserInterface/External/CSSDocumentation/LICENSE",
    "Inspector-Esprima": "Source/WebInspectorUI/UserInterface/External/Esprima/LICENSE",
    "Inspector-three.js": "Source/WebInspectorUI/UserInterface/External/three.js/LICENSE",
}
DEPENDENCY_LICENSES = ("libsoup-LGPL-2", "flite")
# LibWebRTC and the libraries compiled into it, shipped by a WebRTC build.
WEB_RTC_LICENSES = ("LibWebRTC", "LibWebRTC-PATENTS", "abseil", "BoringSSL", "crc32c", "libaom",
                    "libaom-PATENTS", "libsrtp", "libvpx", "libvpx-PATENTS", "libwebm", "libwebm-PATENTS",
                    "libyuv", "libyuv-PATENTS", "Opus", "pffft", "rnnoise")
PLAYBACK_RESOURCE = "lib/gstreamer-1.0/libgstplayback.so"
PLAYBACK_LICENSE = "licenses/GStreamer-playback-LGPL-2.1"


def playback_identity(value):
    if not value:
        return None
    return {key: value[key] for key in
            ("version", "archive_url", "archive_sha256", "patch_file", "patch_sha256")}


def playback_target(manifest):
    if not manifest["source"].get("gstreamer_playback"):
        return None
    target = Path(manifest.get("gstreamer_playback_target", ""))
    if (not target.is_absolute() or ".." in target.parts
            or not target.is_relative_to("/usr/lib")
            or target.name != "libgstplayback.so" or target.parent.name != "gstreamer-1.0"):
        raise ValueError("playback overlay requires a system GStreamer plugin location")
    return target



# /proc/cpuinfo flags for each x86-64 microarchitecture level a build may target.
CPU_LEVELS = {"x86-64": set(),
              "x86-64-v2": {"cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3"}}
CPU_LEVELS["x86-64-v3"] = CPU_LEVELS["x86-64-v2"] | {"avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe",
                                                    "xsave"}


def cpu_flags():
    with open("/proc/cpuinfo") as cpuinfo:
        for line in cpuinfo:
            if line.startswith("flags"):
                return set(line.partition(":")[2].split())
    return set()


def verify(directory, source_pin=None):
    manifest = json.loads((directory / "source-runtime.json").read_text())
    pin = json.loads((source_pin or ROOT / "runtime/engine.json").read_text())
    accepted = [pin["source_commit"], *pin.get("compatible_build_commits", [])]
    if (pin.get("schema") != 1 or pin.get("abi") != 1
            or manifest["source"]["source_commit"] not in accepted or manifest["libexec"] != LIBEXEC):
        raise ValueError("prepared source runtime does not match the reviewed source pin")
    if playback_identity(manifest["source"].get("gstreamer_playback")) != playback_identity(pin.get("gstreamer_playback")):
        raise ValueError("prepared playback plugin does not match the reviewed source pin")
    if not manifest.get("relocatable"):
        raise ValueError("prepare the source runtime again with relocatable library paths")
    relocations = manifest.get("relative_relocations", "RELA")
    if relocations == "RELR-glibc-2.36":
        libc = os.confstr("CS_GNU_LIBC_VERSION") or ""
        version = libc.removeprefix("glibc ").split(".")
        if not libc.startswith("glibc ") or tuple(map(int, version)) < (2, 36):
            raise ValueError("this packed source runtime requires glibc 2.36 or newer")
    elif relocations != "RELA":
        raise ValueError("unknown source runtime relocation format")
    # A build for a newer instruction set dies with SIGILL on an older CPU.
    options = manifest.get("build_options", {})
    flags = " ".join(options.get(key, "") for key in ("CMAKE_C_FLAGS", "CMAKE_CXX_FLAGS")).split()
    targets = {flag.removeprefix("-march=") for flag in flags if flag.startswith("-march=")}
    if options.get("ENABLE_X86_64_V3") == "ON":
        targets.add("x86-64-v3")
    for target in targets:
        if target not in CPU_LEVELS:
            raise ValueError(f"source runtime targets an unrecognized CPU: -march={target}")
        if not CPU_LEVELS[target] <= cpu_flags():
            raise ValueError(f"this source runtime requires an {target} CPU")
    required = {"libexec/" + name for name in CHILDREN}
    required.update({"lib/libWPEWebKit-2.0.so.1", "lib/libWPEInjectedBundle.so"})
    if playback_target(manifest):
        required.update({PLAYBACK_RESOURCE, PLAYBACK_LICENSE,
                         "source-patches/" + pin["gstreamer_playback"]["patch_file"].removeprefix("patches/")})
    if pin.get("inspector_resources") or manifest.get("inspector_resources"):
        if manifest.get("inspector_resources") != DATADIR:
            raise ValueError("source runtime is missing the inspector resource mapping")
        required.add(INSPECTOR_RESOURCE)
    if manifest.get("licenses"):
        required.add(manifest["licenses"]["notice"])
        required.update("licenses/" + name for name in [*WEBKIT_LICENSES, *DEPENDENCY_LICENSES])
        if options.get("ENABLE_WEB_RTC") == "ON":
            required.update("licenses/" + name for name in WEB_RTC_LICENSES)
    if not required.issubset(manifest["files"]):
        raise ValueError("source runtime is missing required components")
    for name, expected in manifest["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("source runtime manifest path escapes its directory")
        path = directory / relative
        if not path.resolve().is_relative_to(directory):
            raise ValueError("source runtime library escapes its directory")
        if "link" in expected:
            if not path.is_symlink() or os.readlink(path) != expected["link"]:
                raise ValueError(f"source runtime alias changed: {name}")
            if str(path.resolve().relative_to(directory)) not in manifest["files"]:
                raise ValueError(f"source runtime alias has no verified target: {name}")
        else:
            if path.is_symlink():
                raise ValueError(f"source runtime file changed: {name}")
            verify_file(path, expected)
    return manifest


def run(arguments):
    directory = arguments.directory.resolve()
    manifest = verify(directory, getattr(arguments, "source_pin", None))
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise ValueError("a host command is required")
    environment = dict(os.environ)
    for name in ("WEBKIT_EXEC_PATH", "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS",
                 "WEBKIT_INSPECTOR_RESOURCES_PATH",
                 "WPE_EXPERIMENTAL_CUSTOM_PROPERTY_INHERITANCE", "WPE_CUSTOM_PROPERTY_INHERITANCE_TRACE"):
        environment.pop(name, None)
    environment.update(LD_LIBRARY_PATH=f"{directory}/lib:/usr/lib:/usr/lib/pulseaudio",
                       WEBKIT_INJECTED_BUNDLE_PATH=str(directory / "lib"),
                       GBM_BACKENDS_PATH="/usr/lib/gbm", LIBGL_DRIVERS_PATH="/usr/lib/dri",
                       __EGL_VENDOR_LIBRARY_DIRS="/usr/share/glvnd/egl_vendor.d")
    # Only the helper install directory is replaced; the trusted host retains its normal filesystem.
    launcher = ["/usr/bin/bwrap", "--die-with-parent", "--bind", "/", "/",
                "--dev-bind", "/dev", "/dev", "--proc", "/proc", "--tmpfs", "/usr/local"]
    for path in sorted(Path("/usr/local").iterdir()):
        if path.name != "libexec":
            launcher.extend(["--bind", str(path), str(path)])
    launcher.extend(["--dir", "/usr/local/libexec"])
    if target := playback_target(manifest):
        launcher.extend(["--ro-bind", str(directory / PLAYBACK_RESOURCE), str(target)])
    if Path("/usr/local/libexec").is_dir():
        for path in sorted(Path("/usr/local/libexec").iterdir()):
            if str(path) != LIBEXEC:
                launcher.extend(["--bind", str(path), str(path)])
    if manifest.get("inspector_resources") == DATADIR:
        environment["WEBKIT_INSPECTOR_RESOURCES_PATH"] = DATADIR
        # Overlay the compiled resource path inside this namespace, without creating host directories.
        launcher.extend(["--tmpfs", "/usr/local/share"])
        if Path("/usr/local/share").is_dir():
            for path in sorted(Path("/usr/local/share").iterdir()):
                if str(path) != DATADIR:
                    launcher.extend(["--bind", str(path), str(path)])
        launcher.extend(["--ro-bind", str((directory / INSPECTOR_RESOURCE).parent), DATADIR])
    launcher.extend(["--ro-bind", str(directory / "libexec"),
                     LIBEXEC, "--chdir", os.getcwd(), "--", *command])
    os.execvpe(launcher[0], launcher, environment)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--engine-pin", "--source-pin", dest="source_pin", type=Path,
                        help="engine identity; defaults to runtime/engine.json")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("verify")
    launch = commands.add_parser("run")
    launch.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        if arguments.action == "verify":
            verify(arguments.directory.resolve(), arguments.source_pin)
            print("Runtime verified")
        else:
            run(arguments)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
