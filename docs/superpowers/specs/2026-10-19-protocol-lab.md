# Protocol investigation and offline model

User objective: finish understanding the Touch ID protocol and reproducing its messages as far as possible without new hardware.

Deliver a reproducible, evidence-indexed inventory of external accessory host/HID/SEP interfaces, annotated layouts, and the remaining unknowns. Implement Python codecs for recovered structures, a hardware-free scripted peer with explicit trust boundaries, and command-line encode/decode/demo tools. Compare the host header encoder with Apple's original memory-only serializer if callable safely. Keep cryptographic transcripts opaque; a simulated acceptance must never be represented as actual Apple attestation, matching, or native Touch ID compatibility. No enrollment, real pairing, authentication installation, daemon patching, secret extraction, purchases, or network services.

Use the current local build as the authority. Retain symbol/instruction references, distinguish observations from inferences, test malformed/truncated/out-of-order/unsupported input and reserved bounds. Tests of invented fixtures establish the model only; report native differential evidence separately. Explore all currently accessible protocol sources before identifying a hard limit. Do not declare either milestone fully reproduced on hardware without hardware evidence.
