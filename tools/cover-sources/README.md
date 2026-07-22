# Cover sources (Proteus replay library)

Proteus hides a tunnel inside **real** traffic: it records genuine traffic and replays
its wire shape while your data rides in the encrypted record bodies. The
`mirage-cover-record` binary builds the library the Reality replay pacer wears.

It is **self-contained** - a single Rust binary shipped with Mirage. No yt-dlp, ffmpeg,
tcpdump, or python. It fetches real traffic over its own rustls stack and reads the wire
envelope off the TLS record framing (the same signal a DPI sees, and exactly what the
pacer replays).

Random content is used on purpose: a fixed set of clips would itself be a signature, so
each run pulls *different* random real traffic, and the pacer chains a random shuffle of
several traces per session (so a session never repeats one clip - a periodicity tell).

## Cover classes

Two traffic shapes, recorded into `library/<class>/`. Point the pacer at the class that
matches your Reality pretext (a CDN/video host -> video; a general site -> browse):

```sh
mirage-cover-record ./library --mode video  --count 20   # streaming video (PeerTube HLS)
mirage-cover-record ./library --mode browse --count 20   # web browsing (random Wikipedia)
```

- **video** - steady large TLS records (segmented HLS). Source: public PeerTube instances.
- **browse** - bursty, varied object sizes (a page + its subresources). Source: random
  Wikipedia articles across languages (`Special:Random`, redirects followed).

Override the source: `--hls <url>` (video), `--url <page>` (browse), `--peertube <host>`.

## Self-driving

```sh
mirage-cover-record ./library --loop 30 --max 40         # record, wait 30 min, repeat; keep 40
```

A systemd unit (`mirage-cover-recorder.service`) runs this. Point the tunnel at a class:

```
reality_pace: "replay", reality_pace_profile: "<path>/library/video"
```

**Paranoid mode** sets this for you.

## Provisioning (bridge -> client)

Both endpoints must point at a library. Record on the **bridge** (or any host), ship the
library directory to clients alongside their config; both set `reality_pace_profile` to
their copy. For a coherent up/down envelope both ends need the *same* library (the shared
per-session seed then selects the same chain).

## Walled gardens

YouTube/TikTok need an extractor Mirage deliberately does not bundle (it rots as sites
change). To use one as a source, resolve it out of band and pass the result:
`mirage-cover-record ./library --hls "$(yt-dlp -g <url>)"`.

## Notes

- Volume: a trace under 64 KiB is rejected (the pacer would loop it); the tool retries.
- Size and direction are faithful (TLS record sizes, both directions). Timing is as good
  as your host's clock; the honest weak axis remains inter-packet timing over a real WAN.
