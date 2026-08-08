# Proteus: why it replays instead of generating

Proteus makes a Mirage tunnel wear the wire shape of real traffic. This is the reasoning
behind that design - specifically, why it **replays captured flows** rather than
generating traffic that looks like them, and what that choice costs.

## The problem a carrier does not solve

Reality, Shadowsocks-2022 and Hysteria2 all make the *connection* look legitimate. None of
them changes what the flow looks like over time. A proxy shuttling a user's browsing has a
characteristic shape - request-sized bursts up, page-sized bursts down, gaps where the
user reads - and that shape survives every layer of encryption, because it is made of
packet sizes, directions and timings, not content.

Flow classifiers key on exactly that. So a perfect TLS disguise still leaves a flow that a
traffic-analysis model can pick out of a population of real ones.

## Why generating a fake shape does not work

The obvious fix is to synthesise a plausible envelope: model video streaming, emit packets
matching the model. This does not reach the indistinguishability floor, and the reason is
structural rather than a matter of better modelling.

A detector distinguishing generated traffic from real traffic is exploiting **redundancy**
- the gap between the entropy rate your generator actually has and the entropy rate of the
real process. Real traffic's conditional entropy does not plateau: conditioning on more
history keeps revealing structure, because the process is driven by an application, a
user, a network and a server that are all themselves structured. A generator has a fixed
order. Beyond that order it injects independent randomness the real process would not
have, and *that excess is itself the signal*. Raise the model order and you push the
detectable structure further out, but you never remove it, because you are approximating a
process whose entropy rate keeps descending.

Measured, a first-order detector separates generated cover from real cover essentially
perfectly. The practical corollary is the one that matters:

> Any entropy Proteus injects that the real flow would not have is a fingerprint.
> Only a schedule with **zero excess entropy** - a real capture, replayed - reaches the
> floor.

This is why `proteus = true` resolves to `replay` and not to one of the generative classes.
The `video` and `browse` generative modes remain accepted for compatibility and are the
weaker option; the docs should not steer anyone toward them.

## How a session actually gets shaped

End to end, with no hand-waving about where the traffic comes from.

**1. Somebody records real traffic.** The recorder opens its own TLS connection to a real
site and reads the wire envelope off the cleartext 5-byte TLS record headers - the same
signal a DPI box sees. It writes `(time, size, direction)` triples to a CSV. Nothing is
simulated; these are the sizes and gaps a real session actually produced.

**2. The traces form a library**, one directory per class: `<lib>/browse/`, `<lib>/video/`.

**3. A session picks a chain from it.** Both endpoints derive the same per-session seed
from their handshake, then use it to select and shuffle several traces into one schedule.
Several, not one, so a long session never loops a single clip - a repeating envelope is a
periodicity tell. Because the seed is shared, both ends select the *same* chain.

**4. The pacer emits one record per schedule token**, at the captured time, padded to the
captured size, filling with the user's data when there is any and with padding when there
is not. That is what makes an idle tunnel and a busy one look alike.

**5. Datagram carriers get a second layer.** QUIC cannot be paced record-by-record without
fighting its own congestion control, so it takes the cover's *sizes* (to pad each datagram
to) and its *cadence* (to fill silence), while volume is capped by the pacer above the
transport. A TLS record larger than the path MTU is split into the back-to-back MTU
packets the wire would have made of it, not clamped - clamping starved the byte rate to a
twelfth and collapsed the size distribution to a constant.

## Does an idle user cost less? No, and that is the point

The most common wrong assumption about this design, worth stating before the cost
tables below.

A record leaves on every schedule tick whether or not the application has data.
Idle time is filled with padding; busy time replaces that padding with the user's
bytes. **The wire is identical either way** - which is exactly what makes an idle
tunnel and a busy one indistinguishable. So an idle session costs precisely what
a saturated one costs.

Ramping the envelope with demand is not a missed optimisation, it IS the signal
this exists to destroy. That was measured rather than assumed: an experiment that
steered larger records to moments when data was waiting - changing no timing and
no total bytes, only which record went where - scored **0.699** separability
against a 0.544 control, with size-marginal features winning. Any demand-following
rate leaks the same way, more crudely.

What DOES scale the bill is connected time. Cover only flows while a session is
open, so the cost is `rate x session-hours`, not `rate x 24` unless clients stay
connected around the clock. Shortening sessions is the one honest lever - though
carrier lifetime is itself part of the cover, so churning connections to save
bandwidth trades one observable for another.

## Which carriers actually wear it

Turning Proteus on does not pace everything the bridge can accept. Seven carriers wear the
envelope; four do not, and on those the switch being on changes nothing about what a censor
sees. Nothing warns you, so it is written down here.

| carrier | paced | per-record framing the pacer sizes against |
|---|---|---|
| Reality | yes | one TLS 1.3 record (21 B) |
| WebSocket (and VLESS riding it) | yes | RFC 6455 frame, 2-12 B by length and direction, plus 21 more when the carrier rides client-originated TLS |
| Shadowsocks-2022 | yes | AEAD chunk (34 B) |
| Hysteria2 | yes | none at this layer - QUIC sizes are shaped below the transport |
| h3 / MASQUE | yes | same as Hysteria2 |
| meek | yes | none modellable - HTTP headers and a front's re-framing sit in between |
| DoH | yes | same as meek |
| plain TCP (and VLESS riding it) | **no** | - |
| obfs-tcp | **no** | - |
| dnstt | **no** | - |
| WebRTC | **no** | - |

The four unpaced ones are unpaced on BOTH ends, so they work - pacing is a property both
ends must agree on, and a mismatch hangs rather than degrades. They are simply not covered.

Two of them are excluded for a reason: a DNS tunnel and a WebRTC data channel have their
own strong shapes, and replaying a captured TLS envelope over either would produce a flow
resembling neither the cover nor the carrier - a new fingerprint rather than a disguise.
Plain TCP and obfs-tcp are a different case: they are byte streams the pacer could drive
with `Carrier::raw()`, and they are unpaced because nothing wired them, not because it
would not work.

So if a bridge advertises dnstt or WebRTC alongside Proteus, those paths are uncovered.
The `PROTEUS_REQUIRED` capability bit says the bridge paces - it does not say a given
carrier is one of the seven.

## Where cover comes from, and who fetches it

This part has real consequences for the people this tool is for, so it is worth being
exact.

Recording means making **real HTTPS requests to real sites**. Both the bridge and the
client can do it, and today both do by default. On a client those requests go out
**un-tunnelled, from the user's own address, before any tunnel exists**.

The default sources are Wikipedia and a set of PeerTube instances. Excellent for an
uncensored host. Close to the worst possible choice for a censored one: Wikipedia has been
blocked in China since 2019 and periodically in Turkey, Pakistan and Venezuela, and those
PeerTube instances are obscure enough to be unreachable or conspicuous nearly anywhere.

So set `proteus_sources`:

| value | meaning |
|---|---|
| `global` (default) | Wikipedia + PeerTube. Right for a bridge, wrong for a censored client. |
| `cn` `ir` `ru` `tr` | Dominant domestic platforms, so a recording session looks like ordinary local browsing. |
| `example.org,https://other.test/` | Your own list. Always wins over a preset. |

The presets are **a starting point, not a guarantee**. Reachability changes without notice
and varies by ISP inside one country. If you know your own network, name your own sites.

### Video sources are per-platform, and a regional pack must not reach abroad

Video capture needs an HLS master playlist, and there is no universal route from a video
page to one. So each source names its own discovery method: PeerTube publishes the manifest
in a video-detail object; Rutube's page inlines nothing but its `/api/play/options/` is
public; OK.ru inlines the manifest URL in the page itself, double-escaped inside JSON inside
an HTML attribute. Adding a platform means adding the few requests that platform needs.

| pack | video sources | discovery |
|---|---|---|
| `global` | The PeerTube set | video-detail API |
| `ru` | Rutube, OK.ru | play-options API; inlined manifest |
| `ir` | Aparat | video API, HLS with progressive fallback |
| `cn` | Bilibili | playurl API, **DASH** |
| `tr` | puhutv (NTV, Kral Pop live) | inlined manifest |
| your own list | your pages, then the PeerTube set | inlined manifest |

**Every regional pack is domestic-only.** Falling back to a global platform is the exact
failure `proteus_sources` exists to prevent: the fetch fails, the video class never fills,
and repeatedly reaching for a blocked host is itself the signal. If a region's domestic
sources fail, it records **no video** rather than reaching abroad. Browse still records, and
browse is the more important class anyway - it carries the tunnel's upstream and is all a
lean budget uses. Only a custom list keeps the global set, as a last group, because a list of
browse pages carries no claim that a manifest is findable on any of them.

### Not every platform serves HLS

Bilibili - the only source that is both reachable and ordinary on a Chinese network - serves
no HLS at all. Its DASH representations are byte ranges into one file, so the recorder drives
them with sequential `Range` requests paced at the representation's real bitrate. That is
what a player's buffer does, and it is already how PeerTube's `#EXT-X-BYTERANGE` playlists
are handled. Aparat uses the same path when its signed HLS redirector refuses and only the
per-profile progressive files are available.

### Video cover carries a stall the length of one segment

Measured, and it applies to **every** source including the global default:

| source | segment duration | worst stall in the capture |
|---|---|---|
| PeerTube (global default) | 4.0-4.6 s | 5.8 s |
| OK.ru (`ru`) | ~6 s | 6.1 s |
| Aparat (`ir`) | 10 s | 10.1 s |
| NTV via puhutv (`tr`) | 10 s | 10.0 s |
| Bilibili (`cn`, **ranged**) | recorder's choice | **1.9 s** |

A realtime video capture waits each segment's true duration, because that is what makes the
trace replayable as continuous cover - its average rate is then the stream's real bitrate. The
consequence is that the tunnel inherits the silence: a 10 s segment is a 10 s stall. The
capture is not defective. A real player genuinely is silent between segment fetches, so this
is a faithful recording of a bursty process.

But it means **no HLS source meets the default 2 s latency ceiling** - 4-10 s segments are the
industry norm and sub-2 s is rare. Three things follow, and they are worth being blunt about:

- **Raising the bandwidth budget does not fix it.** A bigger budget buys a fatter variant of
  the same stream, with the same segment durations. Only the *bandwidth* ceiling responds to
  the budget; this one does not.
- **Retrying does not fix it.** Segment duration is a publisher property, not a per-video
  accident, so another draw stalls identically. The recorder therefore does not retry a
  realtime video capture for a stall - it used to spend three full 360 s recording budgets,
  about 18 minutes, arriving at the same trace (measured on Aparat: 10.2 s, 13.3 s, 10.1 s).
- **The ranged path does not have the problem**, because there the recorder chooses the
  request size and sizes it to this very ceiling. That is a genuine latency advantage of
  DASH/progressive sources, not just a way to reach China.

So: use browse cover for latency-sensitive traffic. Video is the class that buys THROUGHPUT,
and the price is a worst-case stall of one segment.

**The request size follows the latency budget, not the other way round.** With HLS the
segment durations are whatever the publisher chose; with ranges the recorder picks them, so
it asks for the number of bytes that represents a fraction of `max_gap_secs` of media. Sizing
by a fixed byte count instead is a trap worth recording: 512 KiB of Bilibili's 158 kbit/s
rendition is **26.5 seconds** of media, so a realtime capture idled 26.5 s between requests
against a 2 s ceiling and every capture was rejected - the video class for `cn` could not
fill at all under auto-sourcing. The chunk also aims at 60% of the ceiling rather than all of
it, because the stall a capture is judged on is the sleep *plus* the time to first byte of
the next response.

So the thing that kept whole regions out was never extraction difficulty - Bilibili's API is
public and unauthenticated. It was that the recorder spoke one container format.

### Platforms that fight extraction

Some platforms actively defeat automated access, and no in-tree adapter keeps up with them
for long. For those, `--hls-cmd` runs a command and records whatever HLS URL it prints:

```sh
mirage-cover-record ./library --mode video --hls-cmd 'yt-dlp -g https://example/watch?v=...'
```

That gives you an extractor's entire catalogue **without Mirage depending on one**. Nothing
is installed, invoked or required unless you set it, so the shipped binary stays
self-contained. Note that YouTube in particular is the wrong cover source in most of the
regions here - it is blocked in China, Russia and Iran, so reaching for it is precisely the
signal being avoided. It is defensible where it is genuinely ordinary, which is what this
flag is for.

The extractor's own requests are not part of the capture: discovery runs before recording and
on a separate event log. They do still go out un-tunnelled, like every other discovery fetch.

### The cover host is announced in the clear

Shaping the flow does nothing about the Reality cover host, which is sent in cleartext in
the TLS SNI. A client on a Chinese network opening a connection whose SNI says
`www.wikipedia.org` has already said the interesting part before a single record is paced.
When a regional pack is set, the client checks `reality_sni` against that pack's hosts and
warns on a mismatch.

### The two directions need different captures

A cover library holds three classes, and `browse` and `upstream` are both browsing
captures of the same sites recorded two different ways. That is not redundancy - the
directions want opposite things and one capture cannot be both.

**Downstream** is what a censor sees most of, and it wants a real browsing envelope -
several pages reached by following real links, with the connection held open across the
gaps between them. What it does *not* want is long gaps: the tunnel stalls for exactly as
long as the cover is silent. Those gaps used to run to 14 seconds and are now bounded by
the tunnel's own latency budget. See "Burstiness is not a trade" below for why that costs
nothing in detectability.

**Upstream** carries the tunnel's own flow control, which is what actually sets download
speed. Gaps destroy it even faster. Measured on the same pages recorded both ways:

| capture | down payload | up payload | 120 KB download |
|---|---|---|---|
| page load only | 117 KiB/s | 3.93 KiB/s | **2s** |
| with reading dwell | 44.7 KiB/s | 0.91 KiB/s | **18s to 389s** |

Spreading the same handful of request bytes over four times the wall clock is what made
the tunnel unusable, and the *variance* (20x, run to run) is what made it look like an
intermittently broken carrier rather than a slow one.

So `upstream` is recorded without dwell: still a real capture, of the active part of a
session rather than the whole of one. `merge_directional` pairs it with the downstream
capture. Self-sourcing does this by default; if you pin `proteus_profile` by hand, set
`proteus_profile_up` to a dense capture or you will inherit the 389-second case.

The conclusion drawn from that table at the time - "downstream was never the constraint,
120 KB needs under 3 seconds of it either way" - was wrong, and wrong in an instructive
way. It read the *mean* rate. A fetch does not experience the mean; it experiences the gap
it lands in, and the dwelled downstream's gaps ran to 14 seconds. Fixing upstream alone
left 45% of the downstream budget undeliverable. See "Burstiness is not a trade" below.

The recorder enforces a floor on upstream **payload** bytes per second - not tokens per
second, which was the original guard and passed a starving profile because the tokens were
there, just too small to carry anything. A token at or below the framing overhead is pure
cover.

### The upstream class is not downstream cover

A library ROOT holds class subdirs, and pointing the downstream profile at the root pools
what is inside them. It used to pool ALL of them, including `upstream/` - which is
recorded dense and gap-free on purpose, making it a 2-3 second page-load burst rather than
a browsing session. Two consequences, both measured:

- A downstream session could wear a capture whose whole span is shorter than one page
  load, which is not the shape it is claiming to be and shortens the replay loop.
- A session's cover RATE became a lottery between classes. The same library produced
  88.7 KiB/s of idle cover in one session and 125.3 KiB/s in another, purely from which
  class got drawn. That variance raises the measurement floor for every separability
  number taken over it, and it is the leading suspect for the leak in "Did bounding the
  gaps cost anything" below.

`read_profile` now excludes `upstream/` when pooling a root for downstream. If that would
leave the pool empty - a library holding only the upstream class, which happens while
bootstrapping - it falls back to pooling everything, because an empty schedule does not
degrade to unpaced, it HANGS the session with zero bytes.

The class name lives in `mirage_common::proteus_switch::UPSTREAM_COVER_CLASS` rather than
being spelled twice: `mirage-cover` writes the directory and `mirage-transport-reality`
excludes it, and the two crates do not depend on each other. A test asserts they agree,
because drift there would silently restore the old behaviour with no error anywhere.

### What a capture has to clear to enter the library

Selection among real flows is the only lever Proteus has, so the acceptance checks are
where the engineering lives. A capture is rejected and re-recorded (up to three attempts,
then kept with a warning, because unpaced is worse than imperfect) when:

| check | why |
|---|---|
| no usable span | A degenerate capture makes every ceiling below pass VACUOUSLY - they are all upper bounds, and zero is under all of them. It would then be written to the library as valid cover. |
| worst DOWNSTREAM gap | The tunnel stalls for exactly as long as the cover is silent. This is the user's worst-case latency. |
| worst UPSTREAM gap | Only checked on the class that SUPPLIES upstream. A handshake is multi-round-trip, so a quiet upstream stalls it as hard as a quiet downstream. This check did not exist: `Cost` measured gaps over downstream records only, while `paced_handshake_budget` correctly took the worst over both. |
| OPENING silence | Time to the first token in the direction this capture supplies. A capture can have a fine worst-gap and still open slowly, and the opening decides whether the tunnel comes up AT ALL. |
| cost, GB/day | The envelope replayed continuously is the bandwidth bill. |
| upstream payload floor | Flow control rides upstream; too little and every download throttles. |
| browse session span | A session that collapsed to a single page load shortens the replay loop, and a short loop is a fingerprint. |

The upstream-gap check closes a genuine hole: acceptance could not see upstream silence at
all, so nothing stopped a capture that supplies upstream from stalling every handshake
round trip. Measuring this repo's video captures shows how sharp the asymmetry is - all of
them have workable downstream gaps and most have unusable upstream ones:

| capture | down gap | up gap | opens (down) |
|---|---|---|---|
| 0.csv | 1.46s | 2.48s | 0.00s |
| 1.csv | 1.67s | 2.58s | 0.00s |
| 3.csv | 1.99s | 5.37s | 0.01s |

A video flow's upstream is a segment request every few seconds. That is fine as long as
video only ever supplies DOWNSTREAM and is paired with the dense `upstream` class, which
is what `classes_for_budget` arranges - and it is why the check is gated on the class that
actually supplies upstream rather than applied to everything.

**What this does not yet prove.** This repo previously recorded that "aggressive was the
only tier that produced a tunnel which would not come up at all" and blamed the cost tier;
the natural reading is that a video flow's quiet opening starved the handshake. These
captures do not show that - they open in hundredths of a second. They were also recorded
*without* `--realtime`, so their gaps are capped at `SEG_GAP_MAX` and their 3741 KB/s rate
is several times a real stream's. A realtime capture is the one that would have genuine
segment-period gaps, and there is not one in the tree to measure. So the checks above are
correct and now diagnosable, but **whether they are sufficient to make video cover come up
reliably is untested**, and claiming otherwise would be guessing.

### An empty library means no tunnel, not a weaker one

This is the sharpest edge in the whole system. Pacing adds framing, and the session
handshake runs *inside* the paced channel. So if the bridge is paced and the client is not,
the client sends a raw handshake into a peer expecting frames, the peer reads it as a frame
header with a nonsense length, and the session dies with **zero bytes through** - measured,
not theorised.

An empty cover library on the client is therefore not "Proteus is off for now". Against a
paced bridge it is *no tunnel at all*, presenting as an unreachable bridge with nothing
pointing at the cause. Both daemons now warn about this explicitly. The structural fix -
negotiating pacing per session so a mismatch degrades instead of hanging - is not yet
built.

A bridge advertises this as a capability (`PROTEUS_REQUIRED`, set by `mirage-keygen
--proteus`), so a client without Proteus enabled refuses the invite up front, naming the
reason and the fix, instead of discovering it inside a handshake.

It is a **precondition, not a negotiation**, and that is deliberate. Letting a client opt
out would hand a censor a downgrade: connect without cover, and the bridge stops pacing
that session. A half-paced flow - downstream wearing cover, upstream naked - is also more
conspicuous than either end alone. Pacing has to stay symmetric, so the right answer is to
refuse clearly rather than quietly do less.

### The client stops recording once it has a bridge

A connected client pulls the bridge's library over the tunnel
(`_mirage_cover._internal`) and then **stops recording its own**. That closes the
un-tunnelled-requests problem for good rather than mitigating it, and it restores joint
replay, since the up and down schedules are only two halves of one flow when both ends
hold the same traces.

It cannot bootstrap itself - fetching needs a tunnel and a paced tunnel needs a library -
so the *first* library still comes from self-sourcing or ships with the config. What it
removes is every recording after that.

## What replay actually means here

Proteus records real traffic - a real video stream, a real browsing session, a real upload
- and stores its wire envelope as `(time, size, direction)` triples. A session then emits
one record per schedule token, at the captured time, at the captured size, filling with
the user's data when there is any and with padding when there is not.

Two consequences follow, and both are load-bearing:

**The envelope is a cap, not a floor.** Because a token fires whether or not the
application has data, an idle tunnel and a busy one put the same bytes on the wire. That
is the property that hides user activity. It is also why a stalled carrier *drops* its
overdue token rather than bursting to catch up: a catch-up burst would make the wire rate a
function of load, which is precisely the signal being hidden.

**The envelope is also the bandwidth budget.** The user's data leaves only on a token, so
the cover's rate is the tunnel's ceiling. A cheaper disguise is a slower tunnel. This is
not a tuning detail - a capture too sparse to carry a multi-round-trip handshake produces a
tunnel that never connects, and presents as an unreachable bridge rather than as a
cover-selection mistake. The recorder therefore rejects captures below a measured upstream
floor rather than letting them reach the library.

## Cost: set a budget, not a tier

Continuous cover costs what the covered activity costs, forever, in both directions. Every
recording reports its own figure.

Measured on real Wikipedia sessions, page weight alone spans **1.87 to 8.21 GB/day**. The
budget is a ceiling on that number, and it works by **rejecting a capture and recording a
different one** - never by making a cheaper-looking flow.

```json
{ "proteus_max_gb_day": 6.0 }
{ "proteus_max_gb_day": "unlimited" }
```

The default is **2.5 GB/day**. Above **6 GB/day** the recorder also sources video, because
that is the point at which a video capture stops blowing the budget on its own; above
**20 GB/day** it takes the best variant rather than the cheapest. Those thresholds are
`classes_for_budget` and `wants_low_bitrate`, and they follow the number directly - there is
no tier in between.

**Tiers are gone, and the table further down is why.** `lean`, `balanced` and the former
`aggressive` all measured at the harness's noise floor, with the mean drifting very slightly
the WRONG way as cover was added (lean 0.546, balanced 0.553, aggressive 0.556). More cover
bought nothing an observer could not already fail to see - so a name that reads as "more
protection" while meaning "more spending" was getting picked for the wrong reason. Naming the
quantity makes the trade explicit.

What the budget does buy is throughput, because the envelope is simultaneously the disguise
and the bandwidth budget: a record goes out per schedule token whether or not the app has
data, so app bytes displace padding rather than adding to it. Total bytes on the wire are the
same idle or busy - which is the point - but it also means the envelope's rate IS the user's
throughput ceiling. On a 2.5 GB/day envelope a 120 KB transfer took 7 s over Reality and 24 s
over WebSocket; the WebSocket carrier was comfortable at 6. So raise the budget when a carrier
is too slow, never to be harder to see.

Old configs still load. `lean`/`cheap`/`metered` resolve to 2.5 GB/day and
`balanced`/`aggressive`/`max` to 6.0, via `legacy_tier_budget`. Note that `aggressive` was
UNCAPPED and is deliberately not honoured as such: it measured no less detectable than lean,
and it was the only setting that produced a tunnel which would not come up at all - a video
flow opens with a quiet stretch that a faithfully replayed handshake cannot crawl past.

Every trace in the library remains a real capture replayed verbatim; a budget only
decides which real flow gets worn. That distinction is the whole argument above: selection
among real flows adds no entropy, so it costs nothing in detectability.

The honest caveat: an adversary who knew you only ever wear sub-2 GB/day flows learns
something from that fact. It is weak - plenty of real users are on metered links and never
stream - and it buys a tunnel that people on expensive data can afford to leave on, which
is worth more than the margin it concedes.

## Dwell, and why the browse capture changed twice

A browse capture originally recorded a page *load* and stopped. Replayed continuously that
is "load pages back to back forever": measured at 577-1014 kbit/s with **0% of the flow
silent**, a shape no browser produces. It was both the expensive option and the less
realistic one.

The capture then recorded a *session*: several real pages reached by following real links,
with the connection held open across a 4-14 s reading gap so whatever the site sends in
that window - keepalives, beacons, or genuine silence - is captured. Measured: **90.4% of
the flow is silent**, with long gaps between bursts of 50-110 records.

That fixed the cost and broke the throughput, for a reason worth stating precisely.

### Burstiness is not a trade, it is pure loss

The tunnel's capacity IS the cover envelope, so a gap in the capture is a stall for the
user. Write `C` for the capacity a window of cover provides and `D` for demand in that
window. Security forces `C` to be independent of `D` (see the alignment result above), so

```
E[delivered] = E[min(C, D)]
```

`min(c, d)` is **concave in `c`**, so by Jensen, for any cover of mean rate `B`:

```
E[min(C, D)]  <=  E[min(B, D)]
```

with equality **only** when `C` is constant. So among all covers costing the same, the
smoothest one delivers the most - at every budget, with no security term on the other side
of the trade. Burstiness buys nothing. It is not a dial between speed and stealth; it is
waste.

That waste is measured directly by simulating a fetch arriving at a random moment and
comparing its mean completion to what the capture's own mean rate would give if the bytes
were evenly spread. Measured on the chained timeline the pacer actually
replays, six captures each way:

| cover | sustained | burstiness | worst gap | 120 KB fetch, p90 | efficiency |
|---|---|---|---|---|---|
| browse, 4-14 s dwell | 41.5 KB/s | 6.9x | 14.28s | 10.64s | 55% |
| browse, dwell under the latency ceiling | 124.7 KB/s | 2.3x | **1.75s** | **2.87s** | 64% |

Efficiency is the fraction of the budget the user can actually reach. The dwelled capture
threw away 45% of what the operator paid for, and it did not buy stealth with it.

Read efficiency as a *waste* ratio, not a usability one: it is measured against the
capture's own mean rate, so it falls as that rate rises even while the absolute experience
improves. That is why the fixed capture reads only 64% while its p90 fetch is 3.7x better.
The absolute numbers are the ones a user feels; efficiency says how much more is still
available for the same money.

The earlier reasoning missed all of this because it checked the *mean* rate: 44.7 KiB/s
covers 120 KB in 2.7 s, so downstream "was never the constraint". The mean was fine. The
bytes just did not arrive when anyone wanted them.

### The bandwidth setting is also the latency setting

The two ceilings pull opposite ways. `proteus_max_gb_day` pushes the mean rate down;
`max_gap_secs` pushes the envelope toward smooth. Page loads cannot satisfy both at a low
budget - a page either loads fast, which costs, or it waits, which is a gap - so at a low
budget the latency ceiling is the one that gives.

That is not a defect to tune away, it is the shape of the problem, and it means the
operator's bandwidth setting buys **latency as well as throughput**. Measured across the
same recorder at three budgets:

| sustained | p90 fetch, 120 KB |
|---|---|
| 41.5 KB/s | 10.64s |
| 65.6 KB/s | 3.85s |
| 124.7 KB/s | 2.87s |

An operator who finds the tunnel laggy should raise the budget, not look for a shaping
knob. There isn't one - that is what the Jensen bound above says.

### What replaced it

Dwell still exists - a browser does pause between pages, and removing the pause entirely
is the 0%-silent shape that started all this. What changed is its ceiling and what fills
the time:

- **The dwell is bounded by the tunnel's own latency budget**, `max_gap_secs`, at 60% of
  it. The remaining 40% is headroom for the next page's time to first byte, because the
  ceiling applies to the gap a censor (and the acceptance check) actually observes, which
  is dwell *plus* fetch latency. Dwelling to the full ceiling overshot it every time -
  measured at 2.31 s against a 2.0 s ceiling, which sent every capture through the retry
  loop and then kept it anyway.
- **Session length is governed by span, not page count.** A capture's span sets the replay
  loop's period, and a short period is its own fingerprint. Holding span fixed leaves the
  choice of what fills it, and real pages beat artificial waiting. So the recorder browses
  until `SESSION_TARGET_SPAN`, up to a page cap.

The cost is more bytes per session, which is now an explicit operator setting rather than
something the recorder economised on silently. That is the trade the dwell was really
making, made visible.

### Did bounding the gaps cost anything a censor can see?

That is the question the change lives or dies on, so it was measured rather than argued.
Four cells on the same cluster and carrier (Reality), 600 s each, run sequentially: the old
library and the new one, each with its own `NULL_CONTROL`. Each library gets its own
control because the floor depends on the replay loop's period, and the two differ.

Read this section as a worked example of how NOT to conclude from one run. The first
pass was four cells, one per configuration, and it looked clean: each configuration had a
single marginal exceedance, on a different feature and a different direction, which is
what multiple comparisons produce. The conclusion drawn - "smoothing the cover is free,
just as Jensen predicts" - was wrong, and replication is what showed it.

**Three replicates of every cell, means across runs:**

| config | direction | control | active | delta |
|---|---|---|---|---|
| old | up | 0.554 | 0.549 | -0.005 |
| old | down | 0.561 | 0.555 | -0.006 |
| new | up | 0.549 | **0.580** | **+0.031** |

And a back-to-back active/control pair on the new library removed all doubt:

| run | up | down | token drops |
|---|---|---|---|
| active | **0.663** | **0.683** | 0 |
| control | 0.520 | 0.525 | 0 |

That is a real activity signal, on `mean_run_length` in both directions, and it is large
rather than marginal. Two candidate mechanisms are ruled out by evidence rather than
argument: the size aligner is inert (`ALIGN_ALPHA_PERMILLE = 0` makes its `deviate`
branch unreachable, so `has_data` is never consulted), and the pump logged ZERO dropped
tokens in every run, which eliminates the drop rate its own comment nominates as the
residual.

**The signature is variance, not mean.** Controls sit tight at 0.98-1.03x byte ratio
while active runs swing 0.74-1.19x. User activity is widening the spread of the
observable rather than shifting its average, which is why a metric watching run structure
finds it and a metric watching gross volume does not.

**Why the old library looked cleaner: it was noisier, not quieter.** Its own control
measured a 21% byte imbalance with no user traffic at all, against 1-3% for the new one.
A floor that high hides anything. Smoothing the cover lowered the measurement floor and
made a pre-existing signal visible - which is a better position to be in than not knowing,
but it is not the clean pass the first four cells suggested.

**A methodology correction that applies to every number in this document.** The harness
prints a FLOOR derived from sample size, and the measured controls exceed it: values reach
0.570 against a printed 0.558. Single-run verdicts in the 0.55-0.57 band are therefore not
reliable, whoever quotes them. Compare an active cell against ITS OWN replicated control,
never against the printed floor.

### A session wears ONE class, not a mixture

The heterogeneity fix below excluded the UPSTREAM class from the downstream pool. That was
right but incomplete: the defect is not specific to upstream, it is **pooling classes of
different rates into one chain at all**. Measured on the global pack, all realtime:

| class | rate | span |
|---|---|---|
| browse | 494, 670, 960 kbit/s | 24-32 s |
| video | 330 kbit/s | 360 s |

A chain drawn from that pool swings about **2.9x within one session**, and phase-to-phase rate
variance is exactly what raises the separability floor. A censor does not have to identify the
class - only to notice a flow whose rate steps in a way a real session's does not.

**Measured with the project's own distinguisher**, `mirage-adversary`'s 14-feature classifier
over 300-record windows (6 real browse + 4 real video realtime captures, 40 sessions per cell,
cover seeds 0-39 scored against reference seeds 1000-1039 so no file is compared with itself):

| session construction | best separator | per-window AUC | 16 windows pooled | verdict |
|---|---|---|---|---|
| **pooled** vs real browse | `frac_max_record` | **0.807** | **1.000** | SEPARABLE, +0.263 over the bar |
| **pooled** vs real video | `mean_abs_succ_diff` | **0.759** | **1.000** | SEPARABLE, +0.218 over the bar |
| one class (browse) vs real browse | `lag1_autocorr` | 0.511 | 0.562 | indistinguishable, -0.041 |
| one class (video) vs real video | `mean_run_length` | 0.517 | 0.599 | indistinguishable, -0.029 |
| null control: real vs real | `lag1_autocorr` | 0.511 | 0.562 | indistinguishable, -0.041 |

The floor at this sample size is 0.552. A pooled session was separable from **both** references -
it resembles neither a browsing session nor a streaming one, because it is a chimera of the two -
and pooling 16 windows drove it to a perfect 1.000. The one-class sessions sit on the null
control, which is the correct answer: cover that is a real capture replayed should be exactly as
hard to pick out as the real capture.

The 14 features are all derived from record sizes, so that table is the SIZE axis. Projecting the
same schedules onto their inter-record GAP sequence and running the same estimator over that
instead (`tools/cover-sources/class-mixing-gaps.py`) finds the leak was just as large on timing,
and equally closed:

| session construction | best separator | per-window AUC | 16 windows pooled |
|---|---|---|---|
| **pooled** vs real browse gaps | `lag1_autocorr` | **0.808** | **1.000** |
| one class (browse) vs real browse gaps | `size_stddev` | 0.506 | 0.532 |
| one class (video) vs real video gaps | `frac_max_record` | 0.510 | 0.536 |

(The feature names still say "size" there and mean "gap" - it is the same estimator pointed at a
different observable, which is why it is reported separately rather than folded into the table
above. It is not the shipped metric.)

Both axes agree, which is what you would expect: chaining a 30 s browse capture onto a 360 s
video one changes the record sizes AND the gaps between them, so the mixture is visible whichever
one a censor looks at. This says nothing about the residual timing signal discussed further down,
which is a different measurement against a live tunnel.

So `read_profile` now selects ONE class per session from the shared seed and chains only that
class's traces. Both endpoints sort the same directory names and derive the same seed, so they
choose alike and replay stays joint. Coverage is unchanged - every class is still worn, just
whole-session rather than interleaved, which is also closer to what a real user does: they
watch a video OR read pages, not both in alternating four-second phases.

If the chosen class is empty it falls through to the next, because an empty schedule does not
degrade to unpaced - it HANGS the session with zero bytes through. That fail-closed property
is deliberate and is why filling every class matters for availability, not just for cover.

### The cause was cover heterogeneity - most of it, anyway

A library ROOT pooled every class into the downstream schedule, so a session drew either a
63-167 KB/s browse capture or a 67 KB/s upstream-class one, and phase-to-phase rate swung
with the draw. `read_profile` now excludes the upstream class from downstream cover. All
the runs above predate that fix, because the harness builds its image from
`target/release` - a change is not under test until `cargo build --release` has run, which
is worth knowing before trusting any comparison in this file.

Re-measured with the fix, three replicates each:

| | up | down | ACTIVE/IDLE |
|---|---|---|---|
| before, active | 0.663 | 0.683 | 0.74x |
| before, control | 0.520 | 0.525 | 0.98x |
| after, active | 0.562 | 0.569 | 0.82-1.06x |
| after, control | 0.540 | 0.528 | 0.89-0.99x |

**The gap narrows about fourfold** - up +0.143 to +0.022, down +0.158 to +0.041 - and the
variance asymmetry that was the whole signature largely goes with it.

**Whether anything survives is now a question about the HARNESS, not the shaper.** At three
replicates it looked like a small consistent residual. A fourth pair moved it again: the
active cell came back at 0.525/0.525, both below floor, while its matched control flagged
SEPARABLE at 0.615 - a control, with no user traffic, producing a false positive. Across
four replicates each the difference is +0.014 up and +0.008 down, which at these variances
is not significant.

So the current best estimate is that the class-exclusion fix closed the leak, and that the
"residual" was the measurement moving. Three revisions in one session, each from adding
replicates to the previous conclusion, is the strongest possible argument for the rule
stated under "The floor" below: one run per cell is not a measurement.

Mechanisms ruled out along the way, by evidence rather than argument: the size aligner
(inert - `ALIGN_ALPHA_PERMILLE` is 0, so its `deviate` branch is unreachable and `has_data`
is never read), dropped tokens (zero in every run), Nagle (`TCP_NODELAY` is set, and is the
wrong control anyway - it governs small segments awaiting an ACK, not packing a backlog),
carrier connection count (two client ports, not one per transfer), and TCP frame merging
under load (runs longer than one frame measured 0.3% idle against 0.4% active, with an
unchanged size histogram).

### A per-window number is the wrong threat model

0.57 sounds like noise, and for an observer who sees ONE window it is. That is not the
threat. A censor watching a host sees every window that host produces and can average them,
and for independent samples the separation grows as `sqrt(N)`:

```
per-window AUC 0.57  ->  d' ~ 0.25
N = 25   ->  d' ~ 1.25  ->  AUC ~ 0.81
N = 100  ->  d' ~ 2.49  ->  AUC ~ 0.96
```

A session produces hundreds of windows. So a residual that reads as noise per window can be
close to decisive per session, and quoting only the per-window figure understates the
exposure. `flow_classifier::measure_aggregated` measures the real curve instead of trusting
that arithmetic, and `examples/flow_auc` prints it after every verdict.

Three things make the measurement honest rather than alarming:

- **Read EXCESS, not accuracy.** Pooling divides the sample count, and the estimator's floor
  RISES as samples fall, so raw accuracy climbs for two unrelated reasons. Only the margin
  over each level's own floor separates real accumulation from a noisier estimator.
- **Keep enough groups.** Pooling 16 windows out of 122 leaves 7 groups, and at 7 groups the
  measurement is worthless - measured, a control scored a LARGER pooled excess (+0.176) than
  the active run beside it (+0.074). Re-window smaller so pooling still leaves tens of
  groups; the same captures at a 60-record window give 536 windows and 33 groups at N=16.
- **Run the null test at every pooling level, not just per window.** A confound that is
  invisible per window can be amplified by pooling exactly the way real signal is.

Measured on a matched pair at a 60-record window, downstream, excess over each level's own
floor:

| pooled | active run | control run |
|---|---|---|
| 1 | -0.044 | +0.014 |
| 4 | -0.035 | +0.066 |
| 16 | -0.032 | +0.111 |
| 64 | -0.056 | **+0.194** |

The active run is clean at every level. **The control is not**, and that is the finding: with
no user traffic at all it grows to +0.194, so the harness had residual structure between its
two window sets that pooling turns into a confident false positive. See "Matched pairs"
below for the cause and the fix.

`sqrt(N)` is an upper bound in any case: windows from one session share a cover trace, a
host and a network condition, so they are correlated and the true gain is smaller. The
measured curve is the thing to trust; the arithmetic is only a reason to go and look.

### The floor is per-FEATURE, and treating it as one number manufactures leaks

This is the root cause of the false positives above, and it invalidates the precision of
every separability number in this document.

`noise_floor` returns ONE value for a sample size and it is compared against `measure`'s
`max` over 14 features. But those features are not comparable statistics. A mean or a total
concentrates quickly and its sampling distribution is tight. An EXTREME like `max_size` -
or `size_range`, which is `max - min` and inherits it - is set by whichever rare record
happened to land in the window, so its sampling distribution is heavy-tailed and its own
floor is materially higher. Comparing an extreme's score against a floor calibrated on a
synthetic size mixture therefore reports a leak that is not there.

Measured on three NULL CONTROL runs, upstream, window 40 - data with nothing to find, so
every one of these should be chance:

| feature | worst | mean | per run |
|---|---|---|---|
| `max_size` | **0.571** | 0.542 | 0.571 0.524 0.530 |
| `size_range` | **0.571** | 0.542 | 0.571 0.524 0.530 |
| `size_stddev` | 0.550 | 0.527 | 0.550 0.516 0.513 |
| `mean_size` | 0.522 | 0.515 | 0.514 0.522 0.507 |
| `record_count` | 0.500 | 0.500 | degenerate at fixed windows |

Two of fourteen exceed the pooled floor of 0.552 with nothing to detect, and they are
exactly the two extremes. `max_size` was the reported winning separator in both paired
control runs (0.642 and 0.563). Those were not leaks.

The regime matters as much as the feature: at a 60-record DOWNSTREAM window nearly every
window's maximum is the MSS, so `max_size` is degenerate and pins at 0.500, while
`lag1_autocorr` becomes the least stable. So a feature's floor depends on the window and the
direction, not only on the sample size.

`cargo run -p mirage-adversary --example feature_floor -- <idle.sizes> <active.sizes> ...`
reports this for a set of null-control captures.

### The fix: a null permuted from the data, corrected for having looked 14 times

No extra capture runs are needed to calibrate this, which is what made it look expensive.
Under the null the two classes are the same distribution, so pooling every window and
RELABELLING at random draws from exactly that null. `null_model` does it 200 times and reads
each feature's own tail off the result.

That alone is still not enough, and the reason is worth stating because it is easy to stop
one step early. Thresholding each feature at its own 95th percentile controls THAT feature
at 5%, but the reported statistic is the MAXIMUM over fourteen of them, so the chance that
at least one clears its own bar is far higher. Measured on null data: **per-feature
thresholds fire on 8 trials in 40 (20%), against a nominal 5%.**

So the bar is the max-T quantile (Westfall-Young): each permutation contributes the largest
CENTRED accuracy across features, and a finding must beat the 95th percentile of that
maximum. Centring each feature on its own null median first stops a wide feature winning the
maximum merely for being wide. Measured on the same null data: **4 trials in 40, half the
error rate**, and within binomial noise of nominal at that trial count.

On the two paired control runs, the max-T verdict clears one correctly
(`distinct_sizes`, -0.031 against the bar) and still flags the other by +0.011. That second
result is not the estimator misbehaving: a permutation test asks whether the labels are
EXCHANGEABLE, so a control that still flags is a run whose two window sets genuinely
differed - a contaminated run, which is exactly what one wants to be told rather than have
folded into the numbers. **A null control that fails max-T should be discarded, not
averaged in.**

Both the AUC and the permutation are cheap now because `single_feature_auc` computes the
Mann-Whitney statistic by rank sum in `O((n+m) log(n+m))` rather than the `O(n*m)` pairwise
sweep it used to; at 500 flows per class the old form made 200 permutations across 14
features unaffordable, which is the practical reason the floor was ever a constant. The two
forms are asserted equal, ties included, in
`auc_matches_the_pairwise_definition`.

### Matched pairs, because randomising was not enough

Randomised window assignment fixed a real confound - strict alternation put the replay
loop's position in lockstep with the label - and it is not sufficient. A flat shuffle
decorrelates the label from loop position ACROSS runs, but each run still draws its own
imbalance, about `1/sqrt(15)` with 15 windows per class, and that imbalance is systematic
WITHIN the run. So a classifier finds it, and pooling amplifies it precisely because it is
systematic.

That is what the +0.194 control was. The fix is the standard one for this shape of problem:
emit windows as matched PAIRS, one idle and one active in random order within each pair.
Adjacent windows sit at almost the same point in the replay loop, so the loop's contribution
is common to both members and cancels in the comparison rather than being something each run
has to get lucky on. Counts stay balanced by construction.

### What the same two runs delivered to the user

The active cells above also transfer real bytes, so they measure the other half:

| 300 s active windows, Reality | old cover | new cover |
|---|---|---|
| 120 KB startup probe | 21s | **4s** |
| transfers completed | 52 ok, **12 failed** | **123 ok, 0 failed** |
| cover cost while idle | 45.6 KiB/s | 88.7 KiB/s |

The failures are the point. A 19% failure rate is the 14.28 s stall timing transfers out -
the "intermittently broken carrier" symptom this repo previously diagnosed on upstream was
happening on downstream too, and bounding the gaps removed it.

**Be precise about what was bought and what was free.** The new cover costs 1.95x the
bandwidth and completes 2.4x the transfers, so most of the raw throughput was PAID for -
which is the 1:1 law working as designed, not a free lunch. The free part is the Jensen
recovery: about 1.2x more delivered per byte of cover spent, matching the 55% -> 64%
efficiency predicted offline. The startup latency and the elimination of failures come
with it, and those are what turn a tunnel from unusable into usable.

### Parallel connections: measured, and not worth building

There is a second way to smooth a bursty envelope: split the same budget across `K`
carrier connections at independent phases. `K` independent flows have a mean growing as
`K` and a deviation as `sqrt(K)`, so the aggregate's variation falls by `~sqrt(K)`. Unlike
superimposing traces onto ONE connection - a real defect here once, which produced a
4.1-4.7x rate no capture ever had - this is legitimate: each connection still replays a
real capture verbatim, and a browser really does open several.

Measured on the dwelled captures, budget held fixed, it works:

| K | burstiness | efficiency |
|---|---|---|
| 1 | 7.3x | 46% |
| 2 | 3.6x | 83% |
| 4 | 2.7x | 86% |
| 16 | 1.7x | 87% |

**But it is the same 45% twice.** Multi-connection recovers the Jensen gap; so does
recording smoother cover, which is a recorder change rather than an architectural one. On
the fixed captures there is only ~10% left for it to win, and the dense upstream captures
measure at ~100% efficiency at `K=1` - nothing to recover at all. A session spanning
several carrier connections needs cross-connection sequencing and reassembly, and it would
be bought for a tenth of what the cheap fix already delivered. Not built, deliberately.

## What is measured, and what is not

> ### Results predating the host-aware cover library do not transfer
>
> Every separability number recorded in this document and in the repository's history
> was captured with the pacer resolving to **generic** cover, not target-conditioned
> cover. `read_profile` prefers `<library>/<cover-host>/` and silently fell back to the
> generic class when that directory was absent — and the automatic sourcing path could
> never create it, because it only ever wrote class-keyed directories (`browse/`,
> `video/`, `upstream/`). The mode was reachable only by hand-building the layout from a
> tools README, and nothing in the config, the logs or the diagnostics distinguished the
> two. So every measurement described the mode this file's own selection comment calls
> separable, and none described the shippable one.
>
> Auto-sourcing now records the cover host, `--check-config` reports which branch is
> live, a pinned library missing its host directory is refused at startup, and the
> capture manifest records the resolved branch. **Re-measure before quoting any number
> below.** The `0.57` podman residual in particular is a generic-fallback figure.
>
> ### The envelope is an HTTP/1.1 approximation of an HTTP/2 site
>
> The recorder offers **no ALPN** and writes HTTP/1.1 request lines by hand, while every
> major cover host — `www.wikipedia.org`, `www.microsoft.com`, `www.cloudflare.com` —
> serves HTTP/2 to any real browser. The recorded envelope therefore has the wrong
> framing (no HEADERS/DATA frames, no HPACK'd header sizes), the wrong multiplexing (h1
> keep-alive serialises subresources where h2 interleaves them on one connection) and
> the wrong upstream cadence (no SETTINGS, no WINDOW_UPDATE flow-control chatter).
> Replay fidelity does not help: the trace is faithful to a protocol the site does not
> speak to browsers.
>
> The carrier's own ClientHello advertises `h2, http/1.1`. TLS 1.3 encrypts the ALPN
> response, so this is not a single readable field — it is a population comparison: a
> client that offered h2 and then produced an envelope with no h2 characteristics.
>
> **This residual is known and unmeasured.** It cannot be found by the harnesses below,
> for a structural reason worth stating plainly: they compare Mirage against Mirage, so
> any defect that is a property of the DESIGN appears identically in both arms and
> cancels. Finding it needs a different negative class — real browser traffic to the
> same host from the same network position — which has never been run.

Grounded, with numbers in the repository's history: **size and direction**. The
`cover-traffic.sh` harness runs a real cluster, captures the carrier from the censor's
vantage point across idle and active windows, and runs the project's own learned
distinguisher over the two.

### The tools, and which question each answers

| tool | question |
|---|---|
| `scripts/podman-e2e/cover-traffic.sh` | Can a censor tell an idle tunnel from a busy one, on a real cluster? Run it with `NULL_CONTROL=1` first, every time. |
| `examples/flow_auc` | Scores a captured pair. Prints the pooled-floor verdict, the max-T permutation verdict, and the pooling curve. |
| `examples/feature_floor` | Which FEATURES are unstable on captures with nothing to find? Run before believing a near-floor result. |
| `scripts/wire-auc/` | The same idle-vs-busy question with no root, no containers and no capture privileges - for hosts where the podman harness cannot run. |
| `tools/cover-sources/class-mixing-auc.py` | Does a session's cover look like one real session, or like a mixture of two? Size axis. |
| `tools/cover-sources/class-mixing-gaps.py` | The same question on the timing axis. |

Four rules, each of which was learned by getting it wrong in this repository:

1. **One run per cell is not a measurement.** A single four-cell pass here produced a
   confident "no measurable cost" that replication refuted, then a confident "the new cover
   leaks more" that matched controls refuted in turn.
2. **Judge against a replicated control, not the printed floor.** The floor is a
   sample-size estimate; measured controls run above it.
3. **Prefer the max-T verdict** over the pooled-floor one. The pooled floor is a single
   constant against a maximum over fourteen features and fires on 20% of null data.
4. **A null control that still flags is a contaminated run.** Discard it; do not average it
   into a result.

Note for anyone re-running any of this: the harness builds its image from `target/release`,
so a source change is not under test until `cargo build --release` has run. `cargo test` and
debug builds do not affect it.

Three cautions on reading any number it prints. The first two are about what to compare;
the third is about whether the harness is measuring the tunnel or itself.

- **Cover-vs-cover is not a result.** Comparing a replayed trace against the trace it came
  from is trivially 0.5 and means nothing. The measurement has to be tunnel-vs-real-cover,
  or idle-vs-active on a live tunnel.
- **The phase must outlast the cover's silence.** Now that a realistic browse envelope is
  ~90% silent with gaps of tens of seconds, a 20-second phase can contain one burst or
  none, and a verdict drawn from that is noise. Sample lengths have to exceed the cover's
  gap structure.
- **Windows are randomly assigned, and the negative control has to pass.** The envelope is
  a looped replay, so a fixed alternation of idle and active windows puts the replay's
  position in its own loop in lockstep with the label - the lean browse traces span 13-38 s
  against what used to be a 40 s cycle - and the distinguisher learns *where in the cover
  trace it is* rather than whether anyone was using the tunnel. Assignment is randomised
  and balanced now, and `NULL_CONTROL=1` re-runs the identical protocol with no user
  traffic at all in the active windows: with nothing to detect the harness must report
  ~0.5, and whatever it reports above that is the floor under every other number it prints.

## Separability by budget and carrier

Every cover budget against every carrier the harness can stand up, from the censor's vantage
point: can an observer tell an idle tunnel from one carrying real traffic? Produced by
`scripts/podman-e2e/tier-matrix.sh`, rendered with `scripts/podman-e2e/matrix-md.py`, and
regenerable - do not hand-edit the table.

meek and DoH are absent because both need real CDN domain-fronting and there is no origin
to front inside the cluster. Standing up a fake one would measure the fake. They are
covered instead by a paced client-server pair test in `crates/transport-meek`, which
proves the framing is symmetric and carries data but is not a censor-vantage number.

<!-- MATRIX-TABLE-START -->
These rows are labelled with the tier names in force when they were measured (`lean` = 2.5
GB/day, `balanced` = 6.0, `aggressive` = uncapped); the names are gone but the measurements
stand. The `aggressive` rows are retained deliberately: that setting no longer exists, and this table
is the evidence for removing it. It measured no less detectable than `lean` while costing
unbounded bandwidth, and it is the only tier that produced a tunnel which would not come up.

**Control** (same host, same libraries, same window count, no user traffic in the active windows): up 0.569, down 0.581, throughput ratio 0.82x. Nothing existed to detect, so that is this run's floor.

| tier | carrier | up | down | best separator (down) | ACTIVE/IDLE |
|---|---|---|---|---|---|
| lean | reality | 0.569 (120 flows) (at floor) | 0.519 (120 flows) (at floor) | `distinct_sizes` | 0.94x |
| lean | ws | - | - | FAILED: 37 of 55 transfers failed - the tunnel was | - |
| lean | ss2022 | 0.536 (120 flows) (at floor) | 0.559 (120 flows) (at floor) | `total_bytes` | 1.29x |
| lean | hysteria2 | - | - | FAILED: 35 of 59 transfers failed - the tunnel was | - |
| lean | h3 | - | - | FAILED: 36 of 64 transfers failed - the tunnel was | - |
| balanced | reality | 0.561 (120 flows) (at floor) | 0.576 (120 flows) (at floor) | `mean_abs_succ_diff` | 0.91x |
| balanced | ws | 0.545 (120 flows) (at floor) | 0.536 (120 flows) (at floor) | `size_stddev` | 1.04x |
| balanced | ss2022 | 0.551 (120 flows) (at floor) | 0.516 (120 flows) (at floor) | `total_bytes` | 0.93x |
| balanced | hysteria2 | 0.547 (141 flows) (at floor) | 0.587 (120 flows) | `mean_abs_succ_diff` | 0.94x |
| balanced | h3 | 0.536 (142 flows) (at floor) | 0.570 (120 flows) (at floor) | `mean_abs_succ_diff` | 0.98x |
| aggressive | reality | 0.526 (121 flows) (at floor) | 0.573 (120 flows) (at floor) | `size_stddev` | 1.11x |
| aggressive | ws | - | - | FAILED: tunnel did not carry traffic (0 bytes) | - |
| aggressive | ss2022 | 0.567 (120 flows) (at floor) | 0.571 (120 flows) (at floor) | `distinct_sizes` | 0.88x |
| aggressive | hysteria2 | 0.541 (123 flows) (at floor) | 0.532 (120 flows) (at floor) | `distinct_sizes` | 1.08x |
| aggressive | h3 | 0.560 (134 flows) (at floor) | 0.574 (120 flows) (at floor) | `mean_abs_succ_diff` | 1.05x |

Read every cell against two floors. This run's control scored 0.581 with nothing to find; separately, the estimator maximises over 14 features and so scores above 0.5 on any data at all - 0.681 at 16 flows per class, 0.552 at 150. A cell is marked *(at floor)* when it clears neither, which means it is indistinguishable from no signal at its own sample size.

**Verdict: no carrier leaks user activity above the harness's own noise, at any budget.**
Every measured cell sits at or below the floor. The single exception, balanced/hysteria2
downstream at 0.587 against a 0.581 floor, clears it by 0.006 and is answered by the same
carrier at aggressive reading 0.532 - it is run-to-run variance, not a leak.

Read the throughput ratios alongside the accuracies. They run 0.88x to 1.29x against a
control of 0.82x, so activity is not modulating the volume either - which is the cruder
signal an observer would reach for first.

### What the four blank cells mean

Three lean cells (ws, hysteria2, h3) were discarded by a liveness check that was wrong: it
required most active-window transfers to COMPLETE, which measures carrier speed rather than
tunnel health. Under the corrected envelope 120 KB takes 7 s on reality, 12 s on hysteria2
and 24 s on ws against a 10 s timeout, so reality passed and the rest were thrown away
while their tunnels were fine. A timed-out transfer still moves ten seconds of real user
data, so those windows were never cover-only. Fixed; those cells are re-measured separately.

The `aggressive/ws` cell is a genuine failure, and a more interesting one. The tunnel never carried
bytes at all, while both endpoints agreed on the profile digest with a healthy upstream -
so not starvation and not an asymmetry. Aggressive is the only tier whose downstream pool
contains VIDEO captures, and a video flow opens with a long quiet stretch. Replaying that
faithfully means the first tokens are sparse and a handshake can crawl past the readiness
deadline. If it reproduces it is a cover-SELECTION problem, not a carrier one: some real
captures make bad cover for the start of a connection, however good they look later.

### Reading these against the older numbers in this repo's history

Do not compare them. Earlier idle-vs-active figures (0.607 to 0.877) were taken before
three separate defects were fixed: the pacer sized every record against TLS's framing
whatever the carrier was, the replay chain was superimposed rather than concatenated so the
envelope was roughly four times the recorded rate, and the harness alternated its windows
in lockstep with the replay loop. The `lean/ss2022` cell read 0.867/0.877 with a
size-based separator under those conditions and reads 0.536/0.559 here.
<!-- MATRIX-TABLE-END -->

## What it actually costs in throughput

The separability table says the budget does not change what a censor sees. This one says what
it does change, and it is the number an operator will care about first.

| tier | carrier | median | best | worst | completed |
|---|---|---|---|---|---|
| lean | h3 | **13 KB/s** | 82 | 4 | 7/7 |
| lean | hysteria2 | **11 KB/s** | 46 | 4 | 7/7 |
| lean | reality | **10 KB/s** | 55 | 4 | 7/7 |
| lean | ss2022 | **9 KB/s** | 188 | 6 | 7/7 |
| lean | ws | **13 KB/s** | 49 | 4 | 7/7 |
| balanced | h3 | **18 KB/s** | 70 | 8 | 7/7 |
| balanced | hysteria2 | **13 KB/s** | 68 | 9 | 7/7 |
| balanced | reality | **20 KB/s** | 89 | 8 | 7/7 |
| balanced | ss2022 | **21 KB/s** | 85 | 8 | 7/7 |
| balanced | ws | **17 KB/s** | 144 | 8 | 7/7 |

Median of 7 transfers of a 120000-byte body per cell, through the same paced envelope the
separability matrix measures. usage: scripts/podman-e2e/tier-throughput.sh <lib-root> [runs-per-cell].

**The budget is the throughput ceiling, and it is a hard one.** Cover runs for as long as a
session is open, busy or idle, so the sustainable rate is whatever you are willing to spend
while connected (a per session-day figure - two hours online costs two hours of cover):

| budget | ceiling | sustained |
|---|---|---|
| default | 2.5 GB/day | 0.23 Mbit/s |
| video-capable | 6 GB/day | 0.56 Mbit/s |

To sustain 10 Mbit/s of tunnel you would need 10 Mbit/s of cover running permanently -
about 108 GB/day. There is no arrangement of this design that avoids that: a record leaves
per schedule token whether or not the app has data, so app bytes displace padding rather
than adding to it. That property is exactly what makes an idle tunnel and a busy one look
alike, and it is exactly what caps the user.

**Read the spread, not the median.** The browse capture these cells were measured against
was roughly 90% silent, so an identical transfer took wildly different times depending on
whether it landed in a burst or waited for the next one - 4 KB/s to 188 KB/s across these
cells. That spread is the Jensen gap in raw form, and bounding the gaps is what closed most
of it: the same measurement on the current capture puts the worst stall at 1.75 s rather
than 14.28 s. **These cells predate that change and understate what the current recorder
produces**; they are kept because the separability matrix above was taken on the same
captures, and re-quoting one without the other would mix two different runs.

**The carrier does not matter; the envelope does.** Within a budget every carrier lands in the
same band (lean 9-13 KB/s, balanced 13-21 KB/s). There is no faster carrier to switch to,
and an earlier claim in this repo's history that WebSocket ran 3.4x slower than Reality was
an artefact of comparing two single samples from a 14x-spread distribution.

**Balanced buys less than it costs.** 2.4x the bandwidth returns about 1.6x the median
(11.2 -> 17.8 KB/s). What it does buy more honestly is the FLOOR: the worst case roughly
doubles, 4.4 -> 8.2 KB/s, so the painful moments hurt half as much. That, not the median, is
the case for it.

**So be clear about what this is - and what it is not.** At the default budget Proteus is a
low-bandwidth covert channel: messaging, text, light browsing, a two-to-three order of
magnitude reduction on a fast domestic line.

It is not *inherently* low-bandwidth, and the distinction matters. Throughput and cover
cost are the same number, so the ceiling moves with the budget - there is no separate
efficiency to recover, which is exactly what the concavity argument above proves. What
limits the default is that BROWSE cover is slow: web pages are small, so a page-load
envelope sustains around 1 Mbit/s no matter how smooth it is. Real video is the only cover
class that moves at line speed, and at a budget that admits it the same machinery delivers
5 Mbit/s (1080p) to 15-25 Mbit/s (4K).

Whether that path works today is **not yet established**. The historical failure - "the
tier does not come up" - has an obvious candidate now that upstream gaps are measured, and
the acceptance checks that would catch it are in place. But the video captures in this tree
were recorded without `--realtime`, so they are not the shape a replayed stream would
actually wear, and no realtime video capture has been measured end to end. Treat high
budgets as untested rather than as a documented capability until that run exists.

A deployment that needs line rate and will not pay 1:1 for it should still run Reality or
Shadowsocks-2022 WITHOUT Proteus, and accept that flow shape is then exposed to traffic
analysis.

## The open axis: timing under load

Sizes are handled. Each carrier's own per-record framing is now in the pacer's size budget
(`Carrier` in `transport-reality/src/paced.rs`), which was not true before - every carrier
was sized as though it were TLS, so an SS-2022 record went out 13 bytes over target, a
near-MTU token crossed the path MSS, and TCP split it into a full segment plus a tail. With
that fixed the winning separator on SS-2022 stopped being `size_entropy_bits`.

What is left is **timing**, and the mechanism is now partly established - see "Did bounding
the gaps cost anything" above for the measurement that found a real activity signal
(0.663/0.683 against a matched 0.520/0.525 control) and traced it to cover heterogeneity
rather than to the pacer. Three candidate mechanisms have been tested and ruled out on the
carrier that scores worst:

- Not pacer drift. A stalled carrier drops overdue tokens rather than catching up at line
  rate, and a drop *rate* correlated with activity would be exactly this signal - but
  600-second runs logged **zero** dropped tokens on either end, repeatedly.
- Not Nagle coalescing several tokens into one segment under load. Both ends set
  `TCP_NODELAY` on the carrier socket.
- Not demand alignment. `ALIGN_ALPHA_PERMILLE` is 0, which makes the aligner's `deviate`
  branch unreachable, so each token keeps its own captured size and the `has_data` input
  is never consulted. The emission schedule is demand-independent by construction.

What explained most of it was the library: a downstream pool mixing 63-167 KB/s browse
captures with 67 KB/s upstream-class ones made a session's cover rate depend on which class
it drew, and the signature was VARIANCE rather than mean - controls tight at 0.98-1.03x
while active runs swung 0.74-1.19x. Excluding the upstream class from downstream cover
narrowed the gap about fourfold.

A residual survives it, though: three replicates after the fix still put every active run
above its control and every control below (0.562/0.569 against 0.540/0.528). So the timing
axis is narrowed, not closed, and the remaining cause is not yet identified.

A third candidate has been ruled out as well, and it was the harness's own:

- Not a real throughput difference between phases. Under the old fixed alternation the
  ratio came back 0.44x on one carrier and 1.55x on another, which read like carriers
  responding to load in opposite directions. The negative control settles it: with **no
  user traffic at all** the ratio sits near 1.0 on both. The readings were the replay
  schedule beating against the window cycle.

### The floor

With no user traffic in the active windows there is nothing to detect, so whatever the
harness scores is its own floor. Lean library, 15 + 15 randomised 20-second windows:

| control | ACTIVE/IDLE | up | down |
|---|---|---|---|
| ss2022 | 1.12x | 0.538 | 0.526 |
| reality | 0.91x | 0.548 | 0.520 |

**0.52 to 0.55, not 0.5**, and it holds across two carriers whose record structure
differs - so it is a property of the harness rather than of either carrier. A result in
that band is indistinguishable from no signal however it is phrased, and `tier-matrix.sh`
now measures its own control cell first so every table carries the floor for the host and
run that produced it.

**And the floor the harness PRINTS is not the floor either.** That number is derived from
the sample size; the measured controls run above it. Across twelve control measurements the
values reach 0.570 against a printed floor of 0.558, so a single active cell reading 0.56
is not evidence of anything. Two rules follow, and both were learned by getting them wrong
in this repo:

- Judge an active cell against **its own replicated control**, never against the printed
  floor.
- **One run per cell is not a measurement.** A single four-cell pass here produced a
  confident "no measurable cost" that three replicates then refuted, followed by a
  confident "the new cover leaks more" that the matched controls refuted in turn - the old
  cover's own control was 21% imbalanced, too noisy to show anything at all.

So the size axis is closed, and on the timing axis one concrete cause has been found and
removed (cover heterogeneity, above). What remains unquantified is whether anything else
survives above a properly replicated control across all carriers - the matrix that would
answer it has only been run on Reality so far. Cross-carrier comparison is also doubly
unsound while the Reality path target-conditions its replay profile on the cover host, and
so can be replaying a different trace entirely from the carrier it is compared against.

One practical note for anyone re-running this: `scripts/podman-e2e/cover-traffic.sh` builds
its image from `target/release`, so a change is not under test until `cargo build --release`
has run. `cargo test` and debug builds do not affect it.
