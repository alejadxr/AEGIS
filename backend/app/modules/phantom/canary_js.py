"""
Defensive canary JS payload — embedded in HTTP honeypot decoy pages ONLY.

NEVER include this in real AEGIS dashboard templates. The JS collects
voluntarily-disclosed browser features (WebRTC ICE candidates, canvas /
WebGL / audio fingerprint, screen / UA / timezone, automation markers).
No exploits, no XSS, no side-effects to the visitor's machine.

Tor Browser users: WebRTC is fully disabled and canvas/audio are
randomised; the canary returns no real IP and an unstable fingerprint.
Raw scrapers (curl/Python/scrapy) never execute JS at all — no canary.
Headless Chrome / Puppeteer / Playwright execute and trigger the
`headless_detected` flag via `navigator.webdriver` and related markers.
"""

# Endpoint the JS POSTs to. Honeypots can override with a full absolute URL
# (e.g. the Pi honeypot points back to the central AEGIS API).
DEFAULT_ENDPOINT = "/api/v1/phantom/canary"


def build_canary_script(
    endpoint: str = DEFAULT_ENDPOINT,
    honeypot_source: str = "mac_http_8888",
) -> str:
    """Return a `<script>` tag containing the inline canary payload."""
    # Note: kept under 200 lines per task constraint.
    js = """
(function(){
  // AEGIS defensive canary — runs inside a honeypot decoy page.
  // No-op if document is gone (navigated away before window 'load').
  if (!document || !window) return;
  var endpoint = "__ENDPOINT__";
  var source = "__SOURCE__";
  var collected = {
    webrtc_candidates: [],
    fingerprint_hash: null,
    headless_detected: false,
    browser_meta: {},
    honeypot_source: source
  };

  // 1) Headless / automation detection (cheap & synchronous)
  try {
    var hl = false;
    if (navigator.webdriver === true) hl = true;
    if (window.callPhantom || window._phantom) hl = true;
    if (window.__nightmare) hl = true;
    if (navigator.userAgent && /HeadlessChrome|PhantomJS/i.test(navigator.userAgent)) hl = true;
    // Playwright / Puppeteer leak markers
    if (window.navigator && navigator.plugins && navigator.plugins.length === 0
        && navigator.languages && navigator.languages.length === 0) hl = true;
    collected.headless_detected = hl;
  } catch(e){}

  // 2) Browser meta (UA, screen, tz, plugins, languages)
  try {
    collected.browser_meta = {
      ua: navigator.userAgent || null,
      lang: navigator.language || null,
      langs: (navigator.languages || []).slice(0, 8),
      platform: navigator.platform || null,
      cores: navigator.hardwareConcurrency || null,
      memory: navigator.deviceMemory || null,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
      screen: { w: screen.width, h: screen.height, d: window.devicePixelRatio || 1, cd: screen.colorDepth || null },
      do_not_track: navigator.doNotTrack || null,
      plugins: Array.prototype.slice.call(navigator.plugins || []).map(function(p){return p && p.name;}).filter(Boolean).slice(0, 8),
      cookies_enabled: navigator.cookieEnabled === true,
      online: navigator.onLine === true,
      referrer: document.referrer || null
    };
  } catch(e){}

  // 3) Canvas + WebGL + Audio fingerprint -> stable hash
  function hashStr(s){
    var h = 5381; for (var i = 0; i < s.length; i++) h = ((h<<5)+h) ^ s.charCodeAt(i);
    return ('00000000'+(h>>>0).toString(16)).slice(-8);
  }
  try {
    var fp_parts = [];
    var canvas = document.createElement('canvas'); canvas.width = 220; canvas.height = 40;
    var ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.textBaseline = 'top'; ctx.font = '14px Arial';
      ctx.fillStyle = '#069'; ctx.fillText('aegis canary ☃ ' + (navigator.platform||''), 2, 2);
      ctx.fillStyle = 'rgba(102,204,0,0.7)'; ctx.fillText('AEGIS', 4, 18);
      fp_parts.push(canvas.toDataURL());
    }
    var gl_canvas = document.createElement('canvas');
    var gl = gl_canvas.getContext('webgl') || gl_canvas.getContext('experimental-webgl');
    if (gl) {
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      if (dbg) {
        fp_parts.push(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));
        fp_parts.push(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));
      }
    }
    if (window.AudioContext || window.webkitAudioContext) {
      var AC = window.AudioContext || window.webkitAudioContext;
      var actx = new AC();
      fp_parts.push(actx.sampleRate + '|' + actx.baseLatency);
      try { actx.close(); } catch(e){}
    }
    fp_parts.push(collected.browser_meta.tz || '');
    fp_parts.push((collected.browser_meta.screen||{}).w + 'x' + (collected.browser_meta.screen||{}).h);
    fp_parts.push(collected.browser_meta.ua || '');
    collected.fingerprint_hash = hashStr(fp_parts.join('::'));
  } catch(e){}

  // 4) WebRTC STUN leak. Tor Browser blocks RTCPeerConnection entirely;
  //    over plain HTTP from a remote origin, modern Chrome restricts host
  //    candidates to mDNS-obscured tokens — only public/srflx leaks.
  function submit(){
    try {
      var blob = JSON.stringify(collected);
      // Prefer sendBeacon: survives the page being torn down (close/POST).
      if (navigator.sendBeacon) {
        var b = new Blob([blob], {type: 'application/json'});
        navigator.sendBeacon(endpoint, b);
        return;
      }
      var x = new XMLHttpRequest();
      x.open('POST', endpoint, true);
      x.setRequestHeader('Content-Type', 'application/json');
      x.send(blob);
    } catch(e){}
  }
  try {
    var RTCP = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
    if (RTCP) {
      var pc = new RTCP({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
      pc.createDataChannel('');
      pc.onicecandidate = function(e){
        if (!e || !e.candidate || !e.candidate.candidate) return;
        var m = /([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9:]+:[a-f0-9:]+)/i.exec(e.candidate.candidate);
        if (m && m[1] && collected.webrtc_candidates.indexOf(m[1]) === -1) {
          collected.webrtc_candidates.push(m[1]);
        }
      };
      pc.createOffer().then(function(o){ pc.setLocalDescription(o); }).catch(function(){});
      // Give ICE 1.4s to gather, then submit.
      setTimeout(function(){ try { pc.close(); } catch(e){}; submit(); }, 1400);
    } else {
      // No WebRTC (Tor, locked-down browsers): submit what we have.
      setTimeout(submit, 200);
    }
  } catch(e){
    setTimeout(submit, 200);
  }
})();
"""
    js = js.replace("__ENDPOINT__", endpoint).replace("__SOURCE__", honeypot_source)
    return f"<script>{js}</script>"
