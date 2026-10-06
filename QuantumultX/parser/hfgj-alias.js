/* HFGJ alias adapter. Pure parsing only: no network, DNS lookup, or storage. */
var HFGJAlias = (function () {
  "use strict";
  var MAX_CHAIN = 16;
  var ERRORS = {
    E_ALIAS_FORMAT: "alias 格式不受支持（仅精确域名到域名）",
    E_ALIAS_CONFLICT: "同一 alias 源存在不同目标",
    E_ALIAS_CYCLE: "alias 存在循环",
    E_ALIAS_CHAIN: "alias 链超过 16 层",
    E_NESTED_RESOURCE: "此响应只有远程节点引用，无法从同一正文取得节点与 alias",
    E_ALIAS_MODE: "带 alias 的资源暂不支持 profile 或 relay 输出",
    E_NODE_FORMAT: "转换结果不是有效节点列表",
    E_NODE_FIELDS: "节点身份字段重复或为空",
    E_NODE_TRANSPORT: "该节点传输形式尚未验证 alias 身份语义",
    E_NODE_CONVERSION: "带 alias 的节点转换失败，拒绝部分结果",
    E_ALIAS_INTERNAL: "alias 处理失败，拒绝本次结果"
  };
  function failure(code) {
    var err = new Error("HFGJ " + code + ": " + (ERRORS[code] || ERRORS.E_ALIAS_INTERNAL));
    err.hfgjCode = code;
    return err;
  }
  function domain(value) {
    if (typeof value !== "string") return null;
    var normalized = value.toLowerCase().replace(/\.$/, "");
    if (!normalized || normalized.length > 253 || /^[0-9.]+$/.test(normalized)) return null;
    if (!normalized.split(".").every(function (label) {
      return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label);
    })) return null;
    return normalized;
  }
  function add(context, source, target) {
    var from = domain(source), to = domain(target);
    if (!from || !to) throw failure("E_ALIAS_FORMAT");
    if (context.aliases.has(from) && context.aliases.get(from) !== to) throw failure("E_ALIAS_CONFLICT");
    context.aliases.set(from, to);
  }
  function ipLiteral(value) {
    if (typeof value !== "string") return false;
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value)) return value.split(".").every(function (part) { return Number(part) <= 255; });
    return value.indexOf(":") !== -1 && /^[0-9a-f:]+$/i.test(value);
  }
  function resolve(context, host) {
    var current = domain(host), seen = new Set();
    if (!current) return host;
    for (var depth = 0; ; depth++) {
      if (!context.aliases.has(current)) return current;
      if (seen.has(current)) throw failure("E_ALIAS_CYCLE");
      if (depth >= MAX_CHAIN) throw failure("E_ALIAS_CHAIN");
      seen.add(current);
      current = context.aliases.get(current);
    }
  }
  function validate(context) {
    context.aliases.forEach(function (_, source) { resolve(context, source); });
    if (context.aliases.size && /(?:^|[&#])(?:profile|relay)=/.test(context.link)) throw failure("E_ALIAS_MODE");
  }
  function prepare(resource) {
    var context = { aliases: new Map(), link: resource.link || "", error: null, failed: null };
    if (resource.type !== "server") return context;
    try {
      var section = "", nodes = 0, remote = 0;
      String(resource.content || "").split(/\r?\n/).forEach(function (raw) {
        var line = raw.trim();
        if (!line || /^(?:#|;|\/\/)/.test(line)) return;
        var header = /^\[([^\]]+)\]\s*(?:[#;].*)?$/.exec(line);
        if (header) { section = header[1].toLowerCase(); if (section === "server_remote") remote++; return; }
        if (/^(?:shadowsocks|trojan|anytls|vmess|vless|http|socks5)\s*=/i.test(line)) nodes++;
        if (section === "server_remote") remote++;
        if (section !== "dns" || !/^alias\s*=/i.test(line)) return;
        var match = /^alias\s*=\s*\/([^/\s]+)\/([^/\s]+)\s*(?:[#;].*)?$/i.exec(line);
        if (!match) throw failure("E_ALIAS_FORMAT");
        add(context, match[1], match[2]);
      });
      validate(context);
      if (context.aliases.size && remote && !nodes) throw failure("E_NESTED_RESOURCE");
      if (context.aliases.size && !nodes) throw failure("E_NODE_FORMAT");
    } catch (err) { context.error = err.hfgjCode || "E_ALIAS_INTERNAL"; }
    return context;
  }
  function acceptClash(context, config) {
    // Only the confirmed enabled hosts form. IP mappings are not aliases.
    if (!config || !config.dns || config.dns["use-hosts"] !== true || !config.hosts) return;
    try {
      context.clashConfig = config;
      if (typeof config.hosts !== "object" || Array.isArray(config.hosts)) throw failure("E_ALIAS_FORMAT");
      Object.keys(config.hosts).forEach(function (source) {
        var target = config.hosts[source];
        if (typeof target === "string" && domain(target)) add(context, source, target);
        else if (ipLiteral(target)) {
          // Preserve upstream behavior for IP hosts. Never turn nodes into IPs.
        } else if (Array.isArray(target) && target.length && target.every(function (value) {
          return ipLiteral(value);
        })) {
          // Multiple IP mappings are also outside the alias adapter's scope.
        } else throw failure("E_ALIAS_FORMAT");
      });
      validate(context);
    } catch (err) { context.failed = err.hfgjCode || "E_ALIAS_INTERNAL"; throw err; }
  }
  function setOption(line, key, value) {
    if (typeof value !== "string" || !value || /[,\r\n]/.test(value)) throw failure("E_NODE_FIELDS");
    var tagAt = line.search(/,\s*tag\s*=/i);
    var body = tagAt < 0 ? line : line.slice(0, tagAt), tag = tagAt < 0 ? "" : line.slice(tagAt);
    var pattern = new RegExp(",\\s*" + key + "\\s*=[^,]*", "i");
    if (pattern.test(body)) body = body.replace(pattern, function () { return ", " + key + "=" + value; });
    else body += ", " + key + "=" + value;
    return body + tag;
  }
  function protectClashNode(context, source, converted) {
    if (!context.aliases.size) return converted;
    if (!source || typeof source.server !== "string" || !source.server || !/^\d+$/.test(String(source.port)) || Number(source.port) < 1 || Number(source.port) > 65535) throw failure("E_NODE_CONVERSION");
    var normalized = domain(source.server);
    if (!normalized || !context.aliases.has(normalized)) return converted;
    if (["ss", "trojan", "anytls"].indexOf(source.type) === -1 || (source.network && source.network !== "tcp")) throw failure("E_NODE_TRANSPORT");
    if (source.plugin) {
      var pluginOptions = source["plugin-opts"];
      if (source.type !== "ss" || ["obfs", "obfs-local"].indexOf(source.plugin) === -1 || !pluginOptions || ["http", "tls"].indexOf(pluginOptions.mode) === -1 || typeof pluginOptions.host !== "string" || !pluginOptions.host) throw failure("E_NODE_TRANSPORT");
    }
    // Use original parsed values: the upstream YAML repair is deliberately lossy.
    var output = converted.replace(/^([^=]+)=\s*[^,]+/, function (_, type) { return type + "=" + source.server + ":" + source.port; });
    output = setOption(output, "password", source.password);
    if (source.type === "ss") {
      output = setOption(output, "method", source.cipher);
      if (source.plugin) {
        output = setOption(output, "obfs", source["plugin-opts"].mode);
        output = setOption(output, "obfs-host", source["plugin-opts"].host);
      }
    }
    else {
      if (source.sni !== undefined && (typeof source.sni !== "string" || !source.sni)) throw failure("E_NODE_FIELDS");
      output = setOption(output, "tls-host", source.sni === undefined ? source.server : source.sni);
      if (typeof source["skip-cert-verify"] === "boolean") output = setOption(output, "tls-verification", String(!source["skip-cert-verify"]));
    }
    if (typeof source.tfo === "boolean") output = setOption(output, "fast-open", String(source.tfo));
    if (typeof source.udp === "boolean") output = setOption(output, "udp-relay", String(source.udp));
    return output;
  }
  function fields(rest) {
    // Upstream QXFix places tag last; do not interpret tag text as node options.
    var beforeTag = rest.split(/,\s*tag\s*=/i)[0], values = new Map();
    beforeTag.split(",").forEach(function (part) {
      var m = /^\s*([a-z0-9_-]+)\s*=\s*(.*?)\s*$/i.exec(part);
      if (!m) return;
      var key = m[1].toLowerCase();
      if (["obfs", "obfs-host", "tls-host", "over-tls", "tls-verification"].indexOf(key) !== -1) {
        if (values.has(key) || !m[2]) throw failure("E_NODE_FIELDS");
        values.set(key, m[2]);
      }
    });
    return values;
  }
  function isAliasedNode(context, line) {
    if (typeof line !== "string") return false;
    var match = /^[^=]+=\s*([^:\s,]+):[0-9]+/.exec(line);
    return !!match && context.aliases.has(domain(match[1]));
  }
  function node(context, line) {
    var m = /^(\s*)([a-z0-9]+)(\s*=\s*)([^,\s]+)(.*)$/i.exec(line);
    if (!m) throw failure("E_NODE_FORMAT");
    var protocol = m[2].toLowerCase();
    if (["shadowsocks", "trojan", "anytls", "vmess", "vless", "http", "socks5"].indexOf(protocol) === -1) throw failure("E_NODE_TRANSPORT");
    var endpoint = /^([^:]+):([0-9]+)$/.exec(m[4]);
    // Bracketed IPv6 and IP servers cannot match an exact domain alias.
    if (!endpoint || !domain(endpoint[1]) || !context.aliases.has(domain(endpoint[1]))) return line;
    if (Number(endpoint[2]) < 1 || Number(endpoint[2]) > 65535) throw failure("E_NODE_FORMAT");
    var original = endpoint[1], target = resolve(context, original);
    var options = fields(m[5]), additions = [], obfs = (options.get("obfs") || "").toLowerCase();
    if (obfs && ["http", "ws", "wss", "over-tls", "shadowsocks-http", "vmess-http", "tls"].indexOf(obfs) === -1) throw failure("E_NODE_TRANSPORT");
    if (obfs === "tls" && !options.has("obfs-host")) throw failure("E_NODE_TRANSPORT");
    if (["http", "ws", "wss", "shadowsocks-http", "vmess-http"].indexOf(obfs) !== -1 && !options.has("obfs-host")) additions.push("obfs-host=" + original);
    var tls = protocol === "trojan" || protocol === "anytls" || (options.get("over-tls") || "").toLowerCase() === "true" || obfs === "over-tls";
    // For WSS, documented SNI/Host defaults use obfs-host. Preserve that default.
    if (tls && obfs !== "wss" && !options.has("tls-host")) additions.push("tls-host=" + original);
    var rest = m[5];
    if (additions.length) {
      var tagAt = rest.search(/,\s*tag\s*=/i);
      var inserted = ", " + additions.join(", ");
      rest = tagAt < 0 ? rest + inserted : rest.slice(0, tagAt) + inserted + rest.slice(tagAt);
    }
    return m[1] + m[2] + m[3] + target + ":" + endpoint[2] + rest;
  }
  function transform(context, content) {
    if (!context.aliases.size) return content;
    if (typeof content !== "string" || !content.trim()) throw failure("E_NODE_FORMAT");
    var nodeCount = 0;
    var result = content.split(/\n/).map(function (line) {
      if (!line.trim() || /^(?:#|;|\/\/)/.test(line.trim())) return line;
      nodeCount++;
      return node(context, line);
    }).join("\n");
    if (!nodeCount) throw failure("E_NODE_FORMAT");
    return result;
  }
  return { prepare: prepare, acceptClash: acceptClash, protectClashNode: protectClashNode, isAliasedNode: isAliasedNode, transform: transform, resolve: resolve, failure: failure, quietLog: function () {} };
})();
if (typeof module !== "undefined" && module.exports) module.exports = HFGJAlias;
