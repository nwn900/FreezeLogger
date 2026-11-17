# Origin and dependencies

Freeze Logger was written independently for Fallout 4. The user supplied the
Skyrim FreezeLogger repository as product inspiration. Only its public README
was read. No source, binaries, assets, hook offsets, diagnostic algorithms or
report formatting from that project are incorporated here.

Public ABI layout and loader rules were verified against Ian Patterson's F4SE
PluginAPI.h, GameThreads.h, Hooks_Threads.cpp and PluginManager.cpp. api.hpp is a
small independently written declaration of the public interface required for
interoperability. No F4SE implementation or game structure is compiled here.
F4SE itself remains a separately installed prerequisite.

The collector uses Microsoft Windows SDK process snapshotting and DbgHelp,
installed OS components. No third party library is linked.

For 0.2.0, TheWatcher's public README was consulted for early evidence,
presentation progress, partial dump validation and retention requirements.
Its implementation is not incorporated. DXGI provider identity/event numbers
were cross-checked against Intel's published PresentMon provider definitions;
event fields are decoded by Microsoft's TDH API. No PresentMon source is linked
or redistributed. F4SE Scaleform registration uses only its public ABI prefix.

For 0.3.0 the collector's independently written read-only decoder uses factual
field offsets/global RVAs from the public F4SE v0.6.23 declarations. It does not
compile or copy F4SE engine implementation, call engine functions, acquire game
locks or patch memory. The exact executable is hash/PE gated. SDK evidence
hashes and the verified local executable data-section bounds are retained in
context-image-evidence.json. See CONTEXT-163.md for sources and limits.

This provenance records what was used; it does not promise that another person
cannot make a legal complaint.
