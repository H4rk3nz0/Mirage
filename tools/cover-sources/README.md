# Cover sources (the Proteus replay library)

Proteus hides a tunnel inside **real** traffic: it records genuine traffic and replays
its wire shape while your data rides in the encrypted record bodies.

## Turning it on

```json
{ "proteus": true }
```

That is the whole procedure, on the bridge and on the client. With no library
configured, the daemon records and refreshes its own in-process: a dozen traces per
class, topped up in the background, pruned so they neither go stale nor pile up. There
is no recorder to run, no timer to install and no traces to copy anywhere.

Three classes are sourced, because the two directions want opposite things:

- **`browse`** - a real multi-page session *with reading gaps*. The downstream disguise;
  those gaps are what make it look like a person.
- **`upstream`** - the same kind of browsing recorded *without* dwell. The tunnel's flow
  control travels upstream, and reading gaps destroy that capacity: measured, adding dwell
  cut upstream payload from 3.93 to 0.91 KiB/s and turned a 2-second download into one
  that took up to 389. One capture cannot serve both directions.
- **`video`** - a steady large-record envelope, on the balanced and aggressive tiers.

The library lands in `$MIRAGE_STATE_DIR/cover`, else `$XDG_STATE_HOME/mirage/cover`,
else `~/.local/state/mirage/cover`.

`paranoid: true` turns Proteus on along with everything else in the strong posture.

## Recording a specific envelope

Everything below is for an operator who wants a **particular** shape rather than the
automatic one. It is optional.

`mirage-cover-record` is **self-contained** - a single Rust binary shipped with Mirage.
No yt-dlp, ffmpeg, tcpdump, or python. It fetches real traffic over its own rustls stack
and reads the wire envelope off the TLS record framing (the same signal a DPI sees, and
exactly what Proteus replays).

Random content is used on purpose: a fixed set of clips would itself be a signature, so
each run pulls *different* random real traffic, and Proteus chains a random shuffle of
several traces per session (so a session never repeats one clip - a periodicity tell).

### Cover classes

Each class lands in `library/<class>/`. Pick the one that matches your Reality pretext
(a CDN/video host -> video; a general site -> browse):

```sh
mirage-cover-record ./library --mode video  --realtime --low-bitrate --count 20
mirage-cover-record ./library --mode browse --realtime --count 20   # downstream disguise
mirage-cover-record ./library --mode browse --name upstream --count 20  # dense, for upstream
mirage-cover-record ./library --mode upload --url https://your.host/upload
```

- **video** - steady large TLS records (segmented HLS). Source: public PeerTube instances.
- **browse** with `--realtime` - a real multi-page session with reading gaps. The
  downstream disguise.
- **browse** without `--realtime`, into `--name upstream` - the same browsing, dense. The
  tunnel's flow control rides upstream and reading gaps throttle it; see above.
- **upload** - the UPSTREAM envelope of a real file POST, opened by a real page load so
  the trace carries both the small request records and the large upload ones. The only
  class whose records are big enough to size-shape a QUIC carrier's upstream: browse and
  video upstream maxes around 600 bytes against QUIC's 1200-byte floor. Requires
  `--url`, because it sends real bytes and will not pick a stranger's server for you.

Override the source: `--hls <url>` (video), `--url <page>` (browse), `--peertube <host>`.

Every recording prints what the envelope costs per direction if replayed continuously,
along with the worst stall in each direction and how long the capture takes to open. Look
at those before adopting a profile - a bulk-upload capture can easily read 13 GB/day, and a
capture that opens quietly will not carry a handshake at all. `--realtime --low-bitrate`
records video at true playback rate and lowest quality, which is what always-on cover
should be (and what auto-sourcing uses at a modest budget).

Remember that cost and speed are the same number here: the envelope's rate is also the
tunnel's ceiling, 1:1. A cheap capture is a slow tunnel, and there is no efficiency left to
recover - see [Proteus](../../docs/proteus.md).

### Pointing Proteus at it

```json
{ "proteus": "replay", "proteus_profile": "<path>/library/browse",
  "proteus_profile_up": "<path>/library/upstream" }
```

Setting `proteus_profile` turns auto-sourcing OFF - you have told it where to look, so it
believes you. **Set `proteus_profile_up` too.** Self-sourcing pairs the downstream with a
dense upstream automatically; pinning only the downstream inherits the 389-second download
case above.

Pointing `proteus_profile` at a library ROOT rather than a class dir is also supported: it
pools the class subdirs, minus `upstream/`, which is deliberately excluded because it is
recorded dense to carry flow control and is the wrong shape to wear as downstream cover.

The upstream trace is tiled to cover the downstream span, so a short dense capture pairs
with a long dwelled one.

### Target-conditioned replay

If the library root contains a subdir named after the Reality cover host (e.g.
`<lib>/www.wikipedia.org/`), a session whose cover SNI is that host wears THAT site's
recorded shape instead of a generic class - so the flow matches its claimed destination.
Record per-site with `--url https://<host>/... --name <host>` and point the profile at
the root. A host with no subdir falls back to the root, so mixing is safe.

### Self-driving, out of process

Only needed if you are pinning a profile (which disables auto-sourcing) and still want
it refreshed:

```sh
mirage-cover-record ./library --loop 30 --max 40         # record, wait 30 min, repeat; keep 40
```

A systemd unit (`mirage-cover-recorder.service`) runs this.

### Provisioning (bridge -> client)

Mostly automatic now. A connected client pulls the bridge's library over the tunnel and
stops recording its own, which both removes its un-tunnelled requests and makes replay
*joint* - the up and down schedules are only two halves of one flow when both ends hold
the same traces.

It cannot bootstrap itself (fetching needs a tunnel, and a paced tunnel needs a library),
so the FIRST library still comes from the client's own sourcing or ships with its config.
Pinning `proteus_profile` on a client opts out of the sync entirely.

### Walled gardens

YouTube/TikTok need an extractor Mirage deliberately does not bundle (it rots as sites
change). To use one as a source, resolve it out of band and pass the result:
`mirage-cover-record ./library --hls "$(yt-dlp -g <url>)"`.

## Notes

- Volume: a trace under 64 KiB is rejected (Proteus would loop it); the tool retries.
- Size and direction are faithful (TLS record sizes, both directions). Timing is as good
  as your host's clock; the honest weak axis remains inter-packet timing over a real WAN.
