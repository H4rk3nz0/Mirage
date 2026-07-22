# Cover sources (Proteus replay library)

Proteus hides a tunnel inside **real** traffic: it records a genuine video stream and
replays its wire shape while your data rides in the encrypted record bodies. The
`mirage-cover-record` binary builds the library the Reality replay pacer wears.

It is **self-contained** - a single Rust binary shipped with Mirage. No yt-dlp, ffmpeg,
tcpdump, or python. It fetches a real HLS video over its own TLS stack and reads the
wire envelope straight off the TLS record framing (the same signal a DPI sees, and
exactly what the pacer replays).

Random content is used on purpose: a fixed set of clips would itself be a signature, so
each run pulls a *different* random real video (default source: public PeerTube
instances), and the pacer picks a random trace per session.

## Use

```sh
mirage-cover-record ./library                 # one random real PeerTube video
mirage-cover-record ./library --count 20      # 20 random traces
mirage-cover-record ./library --hls <url>     # a specific HLS master playlist
mirage-cover-record ./library --loop 30 --max 40   # self-driving: refresh forever
```

Traces land in `./library/<name>/<i>.csv` (`<name>` = `peertube`, or `hls` for `--hls`).
Point the tunnel at that directory (a random trace is chosen per session):

```
reality_pace: "replay", reality_pace_profile: "<path>/library/peertube"
```

**Paranoid mode** sets this for you and can run the recorder as a service
(`mirage-cover-recorder.service`).

## Provisioning (bridge -> client)

Both endpoints must point at a library. Record on the **bridge** (or any host), then ship
that library directory to clients alongside their config; both set `reality_pace_profile`
to their copy. For a coherent up/down envelope both ends need the *same* library (the
per-session seed then selects the same trace); independent libraries also work but lose
the (sparse) up/down correlation.

## Sources

Default is **PeerTube** (open federation, real HD content, HLS) across a built-in list of
public instances, one picked at random per run. `--peertube <host>` pins one instance;
`--hls <url>` records any HLS master playlist directly.

Walled gardens (YouTube, etc.) need an extractor Mirage deliberately does not bundle (it
rots as sites change). If you want one as a source, resolve it out of band and pass the
result: `mirage-cover-record ./library --hls "$(yt-dlp -g <url>)"`.

## Notes

- Volume: a trace under 64 KiB is rejected (the pacer would loop it, a periodicity tell);
  the tool retries a different video.
- Size and direction are faithful (TLS record sizes, both directions). Timing is as good
  as your host's clock; the honest weak axis remains inter-packet timing over a real WAN.
