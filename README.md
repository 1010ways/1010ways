# Reverse Engineering the Tenways CGO600 Bluetooth Interface

*An open protocol analysis, security review, and interoperability write-up for the Tenways
CGO600 family of e-bikes.*

---

## ⚠️ Legal & Safety Notice — read this first

**This document is published for education, security research, and interoperability
purposes only.** It describes a Bluetooth Low Energy (BLE) protocol as observed on the
author's own bicycle.

- **Do not use this information to exceed legally prescribed speed limits.** E-bike speed
  limits vary by jurisdiction: **25 km/h** in the EU (pedelec/EPAC), **15.5 mph (~25 km/h)**
  in the UK (EAPC), and a **class system** in the US (Class 1–2: 20 mph; Class 3: 28 mph,
  with local variation). Modifying an e-bike to exceed the applicable limit is **illegal on
  public roads** in many places and may void your insurance, warranty, and type approval.
  If you experiment with settings, do so **only on private land** and only after checking
  your local laws.
- **Increasing the maximum assisted speed can significantly affect safety** — braking
  distance, stability, component wear, and rider control. The motor and drivetrain are rated
  for the stock limit; sustained operation above it can cause overheating or failure.
- **You are solely responsible** for how you use this information. The author accepts no
  liability for damages, injuries, fines, or legal consequences arising from its use or misuse.
- **Respect others.** Do not use modified e-bikes in ways that endanger the public.

**Security note for owners:** this analysis found that the bike's BLE settings are writable
**without authentication** (see §9). If you own one of these bikes, be aware that a nearby
party could change its settings over Bluetooth. See §9 for details and the disclosure status.

If you only want to **read telemetry** (battery, odometer, range, etc.) or use documented
features like the light, none of the above concerns apply — those are safe and lawful.

---

## 1. Overview

The Tenways CGO600, CGO600 Pro, and CGO600 PLUS expose a Bluetooth Low Energy interface
(the Nordic UART Service) used by the official Tenways app. The official app only uses a
subset of the available functionality (telemetry, trip reset, unlock). Analysis of the
app and the display firmware reveals a richer, undocumented command set — including a
configurable speed-limit setting — that the bike honors over BLE, **without requiring
authentication**.

This document describes:

- The BLE GATT layout and frame format.
- The checksum scheme (with a non-obvious, direction-dependent byte order).
- The telemetry (read) and settings (write) tag maps.
- A security analysis of the (unauthenticated) write path.
- Which features are reachable over BLE and which are not.

**Scope:** reverse engineered from the official app (`com.ycy.bluetoothbike` v2.17.3), the
SW102 display firmware (`sw102.bin`, CGO600 Pro), and BLE captures from a CGO600 PLUS. The
CGO600 Pro and PLUS use **different displays and controllers**, so some details are
model-specific.

---

## 2. Architecture

```
 TENWAYS app ══BLE (6E40 NUS)══► display ══internal bus (UART)══► motor controller
   R/W/E + CRC16/MODBUS          translates     model-specific protocol
```

The display is a **bridge**: it speaks the app BLE protocol on one side and a controller
protocol on the other. Most telemetry and settings are reachable over BLE; a few things
(e.g. assist-level *commands* on some models) are applied by the display over the internal
bus.

---

## 3. GATT layout

| Role | UUID |
|------|------|
| Service | `6E400001-B5A3-F393-E0A9-E50E24DCCA9E` (Nordic UART) |
| Notify (bike → host) | `6E400003-B5A3-F393-E0A9-E50E24DCCA9E` |
| Write (host → bike) | `6E400002-B5A3-F393-E0A9-E50E24DCCA9E` |

The bike advertises with a name like `CGO600 …`. Connection uses the standard NUS write /
notify characteristics. **No pairing or bonding is required** — any client can connect and
write (see §9).

---

## 4. Frame format

Application frames have a header byte, a length, a payload, a 16-bit checksum, and a
terminator byte `0x45` (`'E'`).

```
phone → bike read   : 52 LEN 07 <tag...>            CRC-LO CRC-HI 45
phone → bike write  : 57 LEN <tag len value...>     CRC-LO CRC-HI 45
bike → phone reply  : 52 LEN NN <tlv...>            CRC-HI CRC-LO 45
bike write-ack      : 57 <tag> <len> <value>        CRC-LO CRC-HI 45   (no LEN byte)
```

- **Header:** `0x52` (`'R'`) for reads, `0x57` (`'W'`) for writes.
- **LEN:** for reads, `1 + number_of_tags` (the `0x07` byte is a command-group byte); for
  writes, the number of TLV bytes.
- **NN (read response only):** the number of TLV fields in the response.
- **Checksum:** CRC-16/MODBUS — reflected polynomial `0xA001` (nominal poly `0x8005`),
  init `0xFFFF` — over all bytes before the CRC pair.
- **Write-ack is structurally different from a request:** it has **no LEN byte**; its layout
  is `57 <tag> <len> <value> <crc> 45`. Parse it by structure, not by the request offsets.

### The direction-dependent CRC byte order

The CRC is stored with **different byte order depending on frame direction**:

| Frame | CRC byte order |
|-------|----------------|
| read request (phone → bike) | **little-endian** |
| write request (phone → bike) | **little-endian** |
| read response (bike → phone) | **big-endian** |
| write ack (bike → phone) | **little-endian** |

**All phone → bike requests use little-endian CRC.** Getting this wrong causes the bike to
silently drop the frame (no error, no ack).

A captured read response (serial number and odometer values anonymized; see the annotated parse below):
`crc16/modbus(body) = 0xB368`, and the stored CRC bytes are `b3 68` → `0xB368` big-endian.
The same check on three independent response frames all validate as big-endian with the `NN`
byte included in the CRC window; computing over the window *without* `NN` matches neither
order.

#### Annotated parse of that response (programmatically derived)
```
52 43 07 10 "00000000000000\r\n"   sn — 14 ASCII digits + CR+LF (0d 0a) = 16 bytes (anonymized)
   12 02 0000                       maxSpd   = 0.0 km/h (trip top speed)
   13 02 0000                       aveSpd   = 0.0 km/h
   14 04 000004d2                   tripDist = 123.4 km
   11 02 0000                       spd      = 0.0 km/h
   16 04 000001f4                   remainRange = 50.0 km
   17 04 000004d2                   ODO      = 123.4 km
   1a 01 32                         battery  = 50 %
   28 01 0a                         (undocumented)
   4f 01 01                         unlock   = 1
   23 02 0000                       power    = 0 W
   15 04 00001c20                   tripDur  = 7200 s (2.0 h)
   b3 68                            CRC (big-endian)
   45                               terminator
```

Notes on the parse:
- The serial-number field's 16-byte length **includes** the trailing `\r\n` (0d 0a) — the
  value is 14 digits plus a CR/LF pair. (Carrying CRLF inside a TLV value is unusual but
  consistent with the declared length.)
- `tripDur` (0x15) is in **seconds**, not minutes.

### Framing is driven by LEN + CRC, not by the terminator

`0x45` is a plausible data byte (it appears in ASCII fields like serial numbers, and inside
CRC values), so **do not frame by scanning for `0x45`**. Reassemble by buffering until the
expected length is reached (from the LEN field / structure) and the CRC validates; treat the
terminator as a consistency check, not a delimiter.

---

## 5. Telemetry (read) tag map

TLV structure is fixed; **multi-byte value endianness is per-tag** (most are big-endian, but
e.g. the speed-limit value `0x25` is little-endian). Distances/speeds are in 0.1 units unless
noted.

| Tag | Field | Unit | Notes |
|-----|-------|------|-------|
| 0x03 | meterFWVer | ASCII | display firmware version |
| 0x07 | sn | ASCII | serial number |
| 0x11 | speed | 0.1 km/h | current |
| 0x12 | maxSpd | 0.1 km/h | **trip top speed (a recording, NOT the limit)** |
| 0x13 | aveSpd | 0.1 km/h | trip average |
| 0x14 | tripDistance | 0.1 km | |
| 0x15 | tripDuration | **seconds** | |
| 0x16 | remainingRange | 0.1 km | |
| 0x17 | totalRange (ODO) | 0.1 km | odometer |
| 0x18 | voltage | raw | |
| 0x19 | current | raw | |
| 0x1A | battery | % | |
| 0x21 | lightControl | 0/1 | writable + readable |
| 0x22 | assistLevel (manual) | int | writable + readable |
| 0x23 | power | W | |
| 0x25 | **maxSpeed (limit)** | km/h (16-bit **little-endian**) | writable + readable |
| 0x26 | wheelSizeIndex | int | writable (no read-back) |
| 0x2A | assistLevel (auto) | int | writable + readable |
| 0x2B | powerOnPassword | ASCII | writable + readable |
| 0x2D | assistModeFlag | int | auto/manual; readable |
| 0x40 | supplierCode | ASCII | |
| 0x41 | productCode | ASCII | |
| 0x4F | whetherUnlock | 1 = unlocked | |
| 0x51 | meterPasswordPageState | int | |

> **Note:** `maxSpd` (0x12) is the **trip maximum speed** (a statistic), *not* the
> configurable speed limit. The speed *limit* is tag `0x25`.

> **Beyond this map:** additional candidate settings tags (`0x1B, 0x20, 0x24, 0x28, 0xFC,
> 0xFD, 0xFE`) exist but their meanings are not yet established; they are not part of the
> confirmed map above.

### Example read (loop query)

Request several telemetry tags at once:
```
52 0d 07 11 12 13 14 15 16 17 21 1a 2d 4f 23 13 fc 45
```

---

## 6. Settings (write) commands

Writes use header `0x57` and little-endian CRC. The following are confirmed working on a
CGO600 PLUS:

| Action | Tag | Value | Notes |
|--------|-----|-------|-------|
| Light on | 0x21 | 1 | confirmed working |
| Light off | 0x21 | 0 | confirmed working |
| Clear trip | 0x32 | 1 | confirmed working |
| Assist level | 0x22 / 0x2A | level | manual / auto mode |
| **Max speed** | **0x25** | km/h (16-bit LE) | **confirmed working** |
| Wheel size | 0x26 | index | affects speed computation |
| Power-on password | 0x2B | ASCII | |

### Examples (little-endian CRC)

```
light on     : 57 03 21 01 01 c1 d2 45
light off    : 57 03 21 01 00 00 12 45
clear trip   : 57 03 32 01 01 30 17 45
```

### Max speed setting (tag 0x25)

The speed limit is stored as a **16-bit little-endian** value in km/h at the same field the
display's own menu edits. Writing tag `0x25` changes it; reading tag `0x25` returns the
current value (25 by default). The little-endian encoding was confirmed by writing a value
and reading it back.

```
max speed N km/h : 57 04 25 02 <lo> <hi> <crcLE_lo> <crcLE_hi> 45
e.g. 25 km/h     : 57 04 25 02 19 00 5d 60 45
```

> ⚠️ **Legal/safety warning:** this setting controls the maximum assisted speed. Changing it
> may be illegal on public roads and can affect safety and component life. See the notice at
> the top of this document. It is documented here for completeness and interoperability
> research; the author does not endorse using it to break the law.

**Persistence & enforcement:** whether a `0x25` write survives a power cycle, and whether the
motor controller enforces its own independent cap (making the display value advisory), has
not been verified here and may vary by model/firmware. "The write was accepted" and "the bike
behaves differently" are distinct claims — treat the former as established and the latter as
requiring your own on-bike verification.

---

## 7. What is NOT reachable over BLE

- **The vendor channel (`0x5A`)** — present on the **CGO600 Pro's SW102 display** (a dormant
  settings channel the official app never uses), but **not implemented on the CGO600 PLUS**
  (its different display ignores these frames). It is a Pro-display-specific dead end for the
  PLUS.
- **Assist-level *commands* on some models** are applied by the display over the internal
  controller bus rather than as a direct BLE write; reading the assist level over BLE works,
  but changing it may require the display's own controls depending on model.

---

## 8. Model differences (Pro vs PLUS)

Different Motor, controller, and firmware. Results here will not necessarily apply to PRO model.

---

## 9. Security analysis: writes are unauthenticated

**The most significant finding of this analysis is not the tag map — it is that the bike's
BLE settings are writable without any authentication.**

- **No pairing, bonding, PIN, or app-level authentication is required** to connect to the
  NUS service and send write commands. Any BLE client within radio range can change the
  bike's settings — including the speed limit, wheel size, assist level, and the power-on
  password — simply by connecting and writing the appropriate `0x57` frames.
- **Impact:** a nearby party could, without the owner's knowledge or consent, alter the
  bike's configuration — most notably raising the maximum assisted speed. This is both a
  safety issue and a potential legal-compliance issue for the owner.

### For owners

Until/unless the vendor addresses this, be aware that your bike's settings can be changed
over Bluetooth by a nearby party. Where possible, avoid leaving the bike's Bluetooth
advertising in public if that is a concern for you.

---

## 10. Building a compatible client

Minimal steps to talk to the bike:

1. Scan for a device named `CGO600 …` and connect to the NUS service.
2. Enable notifications on `6E400003-…`.
3. Send a read request (`0x52`) for the tags you want; reassemble the response by LEN +
   CRC (big-endian), not by scanning for `0x45`.
4. For writes, build a `0x57` frame with **little-endian CRC** and send to `6E400002-…`.

---

## 11. Responsible-use checklist

- ✅ Reading telemetry (battery, odometer, range, speed) — safe & lawful.
- ✅ Using documented features (light, trip reset) — safe & lawful.
- ⚠️ Changing configurable settings (assist, wheel size, speed limit) — **check your local
  laws; private land only; understand the safety and warranty implications.**
- ❌ Riding a modified e-bike above the legal limit on public roads — **illegal in many
  places; don't do it.**
- ❌ Changing settings on a bike you don't own, or without the owner's consent — **do not.**

---

## Credits & sources

- Official Tenways app (`com.ycy.bluetoothbike` v2.17.3) — protocol and command tables.
- SW102 display firmware (`sw102.bin`, CGO600 Pro) — settings struct and write-processor
  analysis.
- BLE captures from a CGO600 PLUS — ground-truth verification.
- Public community discussion noting that BLE settings (including the speed limit) are
  reachable on the CGO600 PLUS — reddit, r/tenwaysebike,
  ["Achieved speed increase for CGO 600 Plus via Bluetooth"](https://www.reddit.com/r/tenwaysebike/comments/1w3of0v/).

### Prior art

The firmware-patching route for these bikes was already publicly documented before this work:
a [Ghidra walkthrough of `sw102.bin`](https://suffix-trie.github.io/) showing how to remove
the speed limit by patching the display firmware, and the
[VELOX project](https://github.com/SenneRoot/VELOX) analysing the same display and its
controller bus. **This document takes a different path:** it maps the app-level BLE protocol
and shows that settings — including the speed limit — can be read and written **over
Bluetooth, with no firmware modification required**. The BLE protocol map and the
unauthenticated-write finding are the novel contributions here.

*This write-up is independent research and is not affiliated with or endorsed by Tenways.*
