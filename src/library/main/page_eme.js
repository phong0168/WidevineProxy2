import { Session } from "./session.js";
import { Util } from "./util.js";

let settings;

const frameId = `[${Math.random().toString(36).slice(2)}]`;

const cdmSessions = new Map();

const mediaKeysServerCertMap = new Map();
const sessionMediaKeysMap = new Map();
const sessionServerCertMap = new Map();

function getWidevineChallengeLocal(licenseRequest, serverCert) {
    const session = new Session({
        deviceType: settings.device.deviceType,
        privateKey: `-----BEGIN RSA PRIVATE KEY-----${settings.device.privateKey}-----END RSA PRIVATE KEY-----`,
        identifierBlob: Util.b64.decode(settings.device.clientId)
    });

    if (serverCert) {
        session.setServiceCertificate(serverCert);
    }

    const result = session.getLicenseChallenge(
        new Uint8Array(licenseRequest),
        settings.server_cert
    );

    if (!result) {
        return licenseRequest;
    }

    cdmSessions.set(result.requestId, session);
    return result.licenseRequest;
}

function parseServerCert(cert) {
    const certBytes = new Uint8Array(cert);

    const signedDrmCert = SignedDrmCertificate.decode(certBytes);
    const drmCert = DrmCertificate.decode(signedDrmCert.drmCertificate);

    const createdDate = new Date(drmCert.creationTimeSeconds * 1000);

    return `Provider ID: ${drmCert.providerId}, Created: ${createdDate.toISOString()}`;
}

async function ensureSettings() {
    if (settings && settings.device_type)
        return settings;
    settings = await Util.emit("SETTINGS", null);
    return settings;
}

function isMediaKeySession(obj) {
    return !!obj && typeof MediaKeySession !== "undefined" && (
        obj instanceof MediaKeySession || MediaKeySession.prototype.isPrototypeOf(obj)
    );
}

async function bufferToUint8Array(data) {
    if (data == null)
        throw new Error("Empty license payload");
    if (typeof Blob !== "undefined" && data instanceof Blob)
        data = await data.arrayBuffer();
    if (data instanceof ArrayBuffer)
        return new Uint8Array(data);
    if (data instanceof Uint8Array)
        return data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
            ? data
            : new Uint8Array(data);
    if (ArrayBuffer.isView(data))
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    if (typeof data === "string") {
        const trimmed = data.trim();
        try {
            return decodeMaybeB64(trimmed);
        } catch (e) {
            return Util.utf8.encode(trimmed);
        }
    }
    return new Uint8Array(data);
}

function decodeMaybeB64(str) {
    const cleaned = String(str).replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
    const padded = cleaned.length % 4 === 0 ? cleaned : cleaned + "=".repeat(4 - (cleaned.length % 4));
    return Util.b64.decode(padded);
}

function previewBytes(bytes) {
    const head = Array.from(bytes.subarray(0, 16))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
    let ascii = "";
    try {
        ascii = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 48)).replace(/[^\x20-\x7e]/g, ".");
    } catch (e) {}
    return `len=${bytes.length} hex[${head}] ascii[${ascii}]`;
}

function looksLikeJson(bytes) {
    let i = 0;
    while (i < bytes.length && (bytes[i] === 0x20 || bytes[i] === 0x09 || bytes[i] === 0x0a || bytes[i] === 0x0d))
        i++;
    return bytes[i] === 0x7b || bytes[i] === 0x5b;
}

function decodeMaybeHex(str) {
    const hex = String(str).replace(/\s+/g, "");
    if (hex.length < 32 || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex))
        return null;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++)
        out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

function longestBase64Blob(str) {
    const compact = String(str).replace(/\s+/g, "");
    const re = /[A-Za-z0-9+/_-]{32,}={0,3}/g;
    let best = "";
    let match;
    while ((match = re.exec(compact))) {
        if (match[0].length > best.length)
            best = match[0];
    }
    return best || null;
}

function xmlTagSummary(text) {
    const tags = [];
    const re = /<\/?([A-Za-z0-9:._-]+)/g;
    let match;
    while ((match = re.exec(text)) && tags.length < 16) {
        if (!tags.includes(match[1]))
            tags.push(match[1]);
    }
    return tags;
}

function extractXmlLicenseValues(text, depth = 0) {
    const out = [];
    const seen = new Set();
    const pushText = (value) => {
        if (value == null)
            return;
        const trimmed = String(value).trim();
        if (trimmed.length < 16 || seen.has(trimmed))
            return;
        seen.add(trimmed);
        out.push(trimmed);
        const blob = longestBase64Blob(trimmed);
        if (blob && blob !== trimmed)
            pushText(blob);
        if (depth < 2 && trimmed.startsWith("<") && trimmed !== text)
            extractXmlLicenseValues(trimmed, depth + 1).forEach(pushText);
    };

    const preferred = [
        "acquirelicenseresult", "license", "licenseresponse", "licensedata",
        "license_data", "binary", "response", "body", "license_response",
        "widevinelicense", "widevine", "challenge", "message"
    ];

    if (typeof DOMParser !== "undefined") {
        try {
            const doc = new DOMParser().parseFromString(text, "text/xml");
            const all = doc.getElementsByTagName("*");
            for (const node of all) {
                const name = (node.localName || node.tagName || "").toLowerCase();
                if (preferred.includes(name) || node.childElementCount === 0)
                    pushText(node.textContent);
            }
            if (doc.documentElement)
                pushText(doc.documentElement.textContent);
        } catch (e) {}
    }

    const cdataRe = /<!\[CDATA\[([\s\S]*?)\]\]>/gi;
    let cdataMatch;
    while ((cdataMatch = cdataRe.exec(text)))
        pushText(cdataMatch[1]);

    const wrappedB64Re = /(?:[A-Za-z0-9+/_-]{4}\s*){8,}={0,3}/g;
    let wrappedMatch;
    while ((wrappedMatch = wrappedB64Re.exec(text)))
        pushText(wrappedMatch[0].replace(/\s+/g, ""));

    const blob = longestBase64Blob(text.replace(/<[^>]+>/g, " "));
    if (blob)
        pushText(blob);

    return out;
}

function collectJsonLicenseValues(obj, out = [], seen = new Set()) {
    if (obj == null)
        return out;
    if (typeof obj === "string") {
        if (obj.length > 8)
            out.push(obj);
        return out;
    }
    if (typeof obj !== "object")
        return out;
    if (seen.has(obj))
        return out;
    seen.add(obj);

    if (Array.isArray(obj)) {
        if (obj.length && obj.every((n) => typeof n === "number"))
            out.push(Uint8Array.from(obj));
        else
            obj.forEach((v) => collectJsonLicenseValues(v, out, seen));
        return out;
    }

    const preferred = [
        "license", "payload", "licenseData", "license_data", "licenseResponse",
        "license_response", "ckc", "message", "response", "data", "body",
        "widevine", "widevineLicense", "signedResponse", "license_b64"
    ];
    for (const key of preferred) {
        if (Object.prototype.hasOwnProperty.call(obj, key))
            collectJsonLicenseValues(obj[key], out, seen);
    }
    for (const value of Object.values(obj))
        collectJsonLicenseValues(value, out, seen);
    return out;
}

function unwrapLicenseCandidates(bytes) {
    const candidates = [bytes];
    const push = (buf) => {
        if (buf && buf.length)
            candidates.push(buf);
    };

    if (bytes.length > 4) {
        const rest = bytes.subarray(4);
        const be = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
        const le = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
        if (be === rest.length || be === bytes.length - 4)
            push(rest);
        else if (be > 0 && be < rest.length)
            push(rest.subarray(0, be));
        if (le === rest.length || le === bytes.length - 4)
            push(rest);
        else if (le > 0 && le < rest.length)
            push(rest.subarray(0, le));
    }

    try {
        const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).replace(/^\uFEFF/, "").trim();
        if (text.startsWith("{") || text.startsWith("[")) {
            const found = [];
            collectJsonLicenseValues(JSON.parse(text), found);
            for (const item of found) {
                if (item instanceof Uint8Array) {
                    push(item);
                } else if (typeof item === "string") {
                    try {
                        push(decodeMaybeB64(item));
                    } catch (e) {}
                }
            }
        } else if (text.startsWith("<")) {
            const found = extractXmlLicenseValues(text);
            console.log("[WVP2]", "SOAP/XML license wrapper", {
                candidates: found.length,
                tags: xmlTagSummary(text),
                head: text.slice(0, 400)
            });
            for (const item of found) {
                try {
                    push(decodeMaybeB64(item));
                } catch (e) {}
                const hex = decodeMaybeHex(item);
                if (hex)
                    push(hex);
            }
        } else if (/^[A-Za-z0-9+/_=-]{16,}$/.test(text.replace(/\s+/g, ""))) {
            try {
                push(decodeMaybeB64(text));
            } catch (e) {}
        }
    } catch (e) {}

    return candidates;
}

function tryDecodeSignedMessage(bytes) {
    const fallbacks = [];
    for (const candidate of unwrapLicenseCandidates(bytes)) {
        try {
            const signedMessage = SignedMessage.decode(candidate);
            if (
                signedMessage.type === SignedMessage.MessageType.LICENSE ||
                signedMessage.type === SignedMessage.MessageType.SERVICE_CERTIFICATE
            ) {
                return { signedMessage, bytes: candidate };
            }
            fallbacks.push({ signedMessage, bytes: candidate });
        } catch (e) {}
    }
    return fallbacks[0] || null;
}

async function handleLicenseUpdate(license, mediaKeySession) {
    const bytes = await bufferToUint8Array(license);
    try {
        parseClearKeyResponse(bytes);
        return;
    } catch (e) {
        // not ClearKey
    }
    await parseWidevineChallenge(bytes, mediaKeySession);
}

async function parseWidevineChallenge(license, mediaKeySession) {
    const originalBytes = new Uint8Array(license);
    const decoded = tryDecodeSignedMessage(originalBytes);

    if (!decoded) {
        const preview = previewBytes(originalBytes);
        let extra = "";
        try {
            const text = new TextDecoder("utf-8", { fatal: false }).decode(originalBytes).trim();
            if (text.startsWith("<")) {
                const playready = /PlayReady|DRM\/2007\/03\/protocols|microsoft\.com\/DRM/i.test(text);
                extra = ` SOAP tags[${xmlTagSummary(text).join(",")}] playready=${playready} xmlCandidates=${extractXmlLicenseValues(text).length}`;
            }
        } catch (e) {}
        console.warn("[WVP2]", frameId, "License decode failed", preview, extra);
        Util.emit("EME_LICENSE", {
            success: false,
            args: "Failed to decode license: invalid protobuf/wrapper. " + preview + extra
        });
        return;
    }

    const signedMessage = decoded.signedMessage;
    const licenseBytes = decoded.bytes;

    if (signedMessage.type === SignedMessage.MessageType.LICENSE) {
        Util.emit("EME_LICENSE", {
            success: true,
            args: Util.safeStringify([license])
        });

        let licenseObj;
        try {
            licenseObj = License.decode(signedMessage.msg);
        } catch (e) {
            console.error("[WVP2]", frameId, "LICENSE body decode failed", e);
            return;
        }
        const requestId = Util.b64.encode(licenseObj.id.requestId);

        if (!cdmSessions.has(requestId))
            return;

        const session = cdmSessions.get(requestId);

        let keys;
        let psshData;

        try {
            if (session.remote) {
                keys = await Util.emit("REMOTE_PARSE", {
                    sessionId: session.sessionId,
                    license: Util.b64.encode(licenseBytes)
                });
                psshData = session.psshData;
            } else {
                keys = session.parseLicense(licenseBytes);
                psshData = Util.b64.encode(session.getPsshData());
            }
        } catch (e) {
            console.error("[WVP2]", frameId, "Parse license keys failed", e);
            return;
        }

        console.log("[WVP2]", frameId, "Widevine Keys", keys);

        Util.emit("KEYS", {
            keys: keys,
            pssh_data: psshData,
            timestamp: new Date().getTime(),
            type: "WIDEVINE",
            url: window.location.href,
            title: document.title
        });

        cdmSessions.delete(requestId);
    } else if (signedMessage.type === SignedMessage.MessageType.SERVICE_CERTIFICATE) {
        const serverCert = new Uint8Array(signedMessage.msg);
        console.log("[WVP2]", frameId, "Server Cert (message):", parseServerCert(serverCert));
        sessionServerCertMap.set(mediaKeySession, serverCert);
    } else {
        Util.emit("EME_LICENSE", {
            success: false,
            args: "Unexpected SignedMessage type: " + signedMessage.type
        });
    }
}

async function getLicenseChallengeRemote(licenseRequest, serverCert) {
    const messageBytes = new Uint8Array(licenseRequest);

    let signedMessage;
    try {
        signedMessage = SignedMessage.decode(messageBytes);
    } catch (e) {
        return licenseRequest;
    }

    if (signedMessage.type !== SignedMessage.MessageType.LICENSE_REQUEST) {
        throw new Error(`Cannot resign message of type ${signedMessage.type}`);
    }

    const parsedRequest = LicenseRequest.decode(signedMessage.msg);
    const psshData = parsedRequest.contentId.widevinePsshData.psshData[0];

    const sessionId = await Util.emit("REMOTE_OPEN", null);

    if (serverCert) {
        await Util.emit("REMOTE_SET_SERVICE_CERTIFICATE", {
            sessionId: sessionId,
            certificate: Util.b64.encode(serverCert)
        });
    }

    const challengeB64 = await Util.emit("REMOTE_GET_CHALLENGE", {
        sessionId: sessionId,
        initData: Util.b64.encode(psshData),
        privacyMode: settings.server_cert
    });

    if (!challengeB64) {
        return licenseRequest;
    }

    const challenge = Util.b64.decode(challengeB64);

    const newSignedMessage = SignedMessage.decode(challenge);
    const newLicenseRequest = LicenseRequest.decode(newSignedMessage.msg);
    const requestId = Util.b64.encode(newLicenseRequest.contentId.widevinePsshData.requestId);

    cdmSessions.set(requestId, {
        remote: true,
        sessionId: sessionId,
        psshData: Util.b64.encode(psshData)
    });

    return challenge;
}

function parseClearKeyResponse(license) {
    const text = new TextDecoder().decode(new Uint8Array(license));
    const clearKey = JSON.parse(text);
    if (!clearKey || !Array.isArray(clearKey.keys))
        throw new Error("not ClearKey");

    Util.emit("EME_LICENSE", {
        success: true,
        args: Util.safeStringify([license])
    });

    const decodeKey = (value) => {
        const paddedB64 = value.replace(/-/g, "+").replace(/_/g, "/") + "==";
        const keyBytes = Util.b64.decode(paddedB64);
        return forge.util.bytesToHex(keyBytes);
    }

    const keys = clearKey["keys"].map(key => ({
        ...key,
        kid: decodeKey(key.kid),
        k: decodeKey(key.k)
    }));

    const psshData =  btoa(JSON.stringify({
        kids: clearKey["keys"].map(key => key.kid)
    }));

    console.log("[WVP2]", frameId, "ClearKey Keys", keys);

    Util.emit("KEYS", {
        keys: keys,
        pssh_data: psshData,
        timestamp: new Date().getTime(),
        type: "CLEARKEY",
        url: window.location.href,
        title: document.title
    });
}

if (typeof MediaKeySystemAccess !== "undefined") {
    Util.proxy(MediaKeySystemAccess.prototype, "createMediaKeys", (_target, _this, _args) => {
        return Util.logEme("EME_CREATE_MEDIA_KEYS", _args, async () => {
            return await _target.apply(_this, _args);
        });
    });
}

if (typeof MediaKeys !== "undefined") {
    Util.proxy(MediaKeys.prototype, "setServerCertificate", async (_target, _this, _args) => {
        console.log("[WVP2]", frameId, "Server Cert (setServerCertificate):", parseServerCert(_args[0]));
        const result = await _target.apply(_this, _args);
        mediaKeysServerCertMap.set(_this, new Uint8Array(_args[0]));
        return result;
    });

    Util.proxy(MediaKeys.prototype, "createSession", (_target, _this, _args) => {
        return Util.logEme("EME_CREATE_SESSION", _args, () => {
            const result = _target.apply(_this, _args);
            sessionMediaKeysMap.set(result, _this);
            return result;
        });
    });
}

if (typeof MediaKeySession !== "undefined") {
    Util.proxy(MediaKeySession.prototype, "generateRequest", (_target, _this, _args) => {
        return Util.logEme("EME_GENERATE_REQUEST", _args, async () => {
            return await _target.apply(_this, _args);
        });
    });

    if (typeof MediaKeyMessageEvent !== "undefined") {
        const getServerCert = (_this) => {
            const mediaKeys = sessionMediaKeysMap.get(_this);
            if (mediaKeys) {
                const serverCert = mediaKeysServerCertMap.get(mediaKeys);
                if (serverCert) {
                    return serverCert;
                }
            }
            return sessionServerCertMap.get(_this);
        }

        const resignChallenge = async (message, serverCert) => {
            try {
                // If we don't fail to parse the message as JSON it's ClearKey and we don't continue
                const text = new TextDecoder().decode(message);
                JSON.parse(text);
                return;
            } catch (e) {
                // ignored
            }

            await ensureSettings();

            if (settings?.device_type === "WVD") {
                return getWidevineChallengeLocal(message, serverCert);
            } else if (settings?.device_type === "REMOTE") {
                return await getLicenseChallengeRemote(message, serverCert);
            }
            return message;
        };

        const patchChallengeMessage = (e, newChallenge) => {
            const buffer = new Uint8Array(newChallenge).buffer;
            try {
                Object.defineProperty(e, "message", {
                    configurable: true,
                    get: () => buffer
                });
                return true;
            } catch (err) {
                return false;
            }
        };

        const interceptChallenge = async (_args, _this, _thisTarget, type) => {
            const [e] = _args;

            if (!(e instanceof MediaKeyMessageEvent) || e.message.byteLength <= 2) {
                return;
            }
            // Synthetic clones are untrusted; still deliver them to the player.
            if (!e.isTrusted)
                return;

            Util.emit("EME_LICENSE_REQUEST", {
                success: true,
                args: Util.safeStringify(e.message)
            });

            const serverCert = getServerCert(type === "object" ? _thisTarget : _this);
            const newChallenge = await resignChallenge(e.message, serverCert);

            if (!newChallenge) {
                return;
            }

            console.log("[WVP2]", "New challenge:", Util.b64.encode(newChallenge));
            console.log("[WVP2]", frameId, `Intercepted (${settings?.proxy_mode}/${type})`, _args[0]);

            const patched = patchChallengeMessage(e, newChallenge);

            // Keep the original trusted event so players that check isTrusted still
            // send the license request. Cloning alone left License stuck on Challenge.
            if (patched)
                return false;

            if (settings?.proxy_mode === "event") {
                const clonedEvent = new MediaKeyMessageEvent("message", {
                    messageType: e.messageType,
                    message: new Uint8Array(newChallenge).buffer
                });

                try {
                    e.stopImmediatePropagation();
                    e.preventDefault();
                } catch (err) {}

                _thisTarget.dispatchEvent(clonedEvent);
                return true;
            }
        }

        const wrappedListeners = new WeakMap();

        const wrapListener = (listener, _thisTarget) => {
            if (!listener)
                return listener;
            if (wrappedListeners.has(listener))
                return wrappedListeners.get(listener);

            let wrapped = listener;
            if (typeof listener === "function") {
                wrapped = new Proxy(listener, {
                    async apply(_target, _this, _args) {
                        let skip = false;
                        try {
                            skip = await interceptChallenge(_args, _this, _thisTarget, "function");
                        } catch (err) {
                            console.error("[WVP2]", frameId, "Challenge intercept failed:", err);
                        }
                        if (!skip)
                            return Reflect.apply(_target, _this, _args);
                    }
                });
            } else if (typeof listener === "object" && typeof listener.handleEvent === "function") {
                Util.proxy(listener, "handleEvent", async (_target, _this, _args) => {
                    let skip = false;
                    try {
                        skip = await interceptChallenge(_args, _this, _thisTarget, "object");
                    } catch (err) {
                        console.error("[WVP2]", frameId, "Challenge intercept failed:", err);
                    }
                    if (!skip)
                        return Reflect.apply(_target, _this, _args);
                });
                wrapped = listener;
            }

            wrappedListeners.set(listener, wrapped);
            if (wrapped !== listener)
                wrappedListeners.set(wrapped, wrapped);
            return wrapped;
        }

        Util.proxy(MediaKeySession.prototype, "addEventListener", (_target, _this, _args) => {
            const [type, listener] = _args;

            if (_this == null || type !== "message") {
                return _target.apply(_this, _args);
            }

            _args[1] = wrapListener(listener, _this);

            return _target.apply(_this, _args);
        });

        if (typeof EventTarget !== "undefined") {
            Util.proxy(EventTarget.prototype, "addEventListener", (_target, _this, _args) => {
                const [type, listener] = _args;
                if (type === "message" && isMediaKeySession(_this)) {
                    _args[1] = wrapListener(listener, _this);
                }
                return _target.apply(_this, _args);
            });
        }

        const onmessageDesc =
            Object.getOwnPropertyDescriptor(MediaKeySession.prototype, "onmessage") ||
            Object.getOwnPropertyDescriptor(EventTarget.prototype, "onmessage");

        Object.defineProperty(MediaKeySession.prototype, "onmessage", {
            configurable: true,
            enumerable: true,
            get: function () {
                if (onmessageDesc && onmessageDesc.get)
                    return onmessageDesc.get.call(this);
                return this.__wvp2_onmessage;
            },
            set: function (listener) {
                const wrapped = wrapListener(listener, this);
                this.__wvp2_onmessage = wrapped;
                if (onmessageDesc && onmessageDesc.set)
                    onmessageDesc.set.call(this, wrapped);
            }
        });
    }

    Util.proxy(MediaKeySession.prototype, "update", async (_target, _this, _args) => {
        if (_this == null) {
            return _target.apply(_this, _args);
        }

        try {
            await handleLicenseUpdate(_args[0], _this);
        } catch (e) {
            Util.emit("EME_LICENSE", {
                success: false,
                args: e?.message || String(e)
            });
        }

        try {
            return await _target.apply(_this, _args);
        } catch (e) {
            // ignored, since this will always fail on the browser CDM
        }
    });
}

(async () => {
    settings = await Util.emit("SETTINGS", null);
})();