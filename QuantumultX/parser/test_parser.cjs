"use strict";
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const adapter = require("./hfgj-alias.js");
const root = path.resolve(__dirname, "..");
const original = fs.readFileSync(path.join(__dirname, "upstream/resource-parser.js"), "utf8");
const generated = fs.readFileSync(path.join(root, "resource-parser-hfgj.js"), "utf8");
let passed = 0;
function test(name, fn) {
  try { fn(); passed++; process.stdout.write("PASS " + name + "\n"); }
  catch (error) { process.stderr.write("FAIL " + name + ": " + error.message + "\n"); process.exitCode = 1; }
}
function resource(content, type = "server", suffix = "") {
  return {content, type, link: "https://subscription.example/resource" + suffix, tag: "test", info: "upload=1; download=2; total=1000; expire=2000000000"};
}
function profile(nodes, aliases = "alias = /a.example/b.example") {
  return "[server_local]\n" + nodes + "\n[dns]\n" + aliases + "\n";
}
function run(source, input, build = 950) {
  const outputs = [], notifications = [], logs = [];
  const context = {
    $resource: {...input}, $environment: {version: "Quantumult X build " + build},
    $done: output => outputs.push(JSON.parse(JSON.stringify(output))),
    $notify: (...args) => notifications.push(args), console: {log: (...args) => logs.push(args)}
  };
  vm.runInNewContext(source, context, {timeout: 10000});
  return {outputs, notifications, logs, context};
}
function output(input) {
  const r = run(generated, input);
  assert.equal(r.outputs.length, 1);
  const value = r.outputs[0];
  if (typeof value.content === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(value.content)) value.content = Buffer.from(value.content,"base64").toString("utf8");
  return value;
}
function direct(content, aliases = "alias=/a.example/b.example") {
  const c = adapter.prepare(resource(profile(content, aliases)));
  if (c.error) throw adapter.failure(c.error);
  return adapter.transform(c, content);
}
function error(input, code) {
  const result = output(input);
  assert.match(result.error, new RegExp(code));
  assert.equal(result.content, undefined);
  assert(!result.error.includes("a.example"));
  return result;
}
test("domain address only; port, password, tag, explicit TLS and checks stay intact", () => {
  const n = "trojan = a.example:443, password=a.example, tls-host=identity.example, tls-verification=true, fast-open=true, server_check_url=https://a.example/check, tag=a.example";
  assert.equal(direct(n), n.replace("a.example:443", "b.example:443"));
});
test("implicit AnyTLS identity stays on original server", () => {
  assert.equal(direct("anytls=a.example:443, password=test, tag=one"), "anytls=b.example:443, password=test, tls-host=a.example, tag=one");
});
test("TLS cert setting is not changed", () => {
  assert.match(direct("trojan=a.example:443, password=test, tls-verification=false, tag=one"), /tls-verification=false/);
});
test("domain-valued cert validation is retained", () => {
  assert.match(direct("trojan=a.example:443, password=test, tls-verification=cert.example, tag=one"), /tls-verification=cert.example/);
});
test("plain Shadowsocks does not acquire TLS fields", () => {
  assert.equal(direct("shadowsocks=a.example:8388, method=aes-128-gcm, password=test, tag=one"), "shadowsocks=b.example:8388, method=aes-128-gcm, password=test, tag=one");
});
for (const protocol of ["http", "socks5", "vmess", "vless"]) {
  test(protocol + " explicit TLS transport keeps implicit identity", () => {
    assert.match(direct(protocol + "=a.example:443, over-tls=true, tag=one"), /tls-host=a.example/);
  });
}
test("legacy obfs=over-tls identity is retained", () => {
  assert.match(direct("vmess=a.example:443, obfs=over-tls, tag=one"), /tls-host=a.example/);
});
for (const obfs of ["http", "ws", "wss", "shadowsocks-http", "vmess-http"]) {
  test(obfs + " missing transport Host is made explicit", () => {
    const n = direct("vmess=a.example:443, obfs=" + obfs + ", tag=one");
    assert.match(n, /obfs-host=a.example/);
    if (obfs === "wss") assert(!n.includes("tls-host="));
  });
}
test("explicit WSS Host and SNI stay intact", () => {
  const n = "vless=a.example:443, obfs=wss, obfs-host=web.example, tls-host=tls.example, tag=one";
  assert.equal(direct(n), n.replace("a.example:443", "b.example:443"));
});
test("uncertain TLS obfuscation default is rejected", () => {
  assert.throws(() => direct("shadowsocks=a.example:443, obfs=tls, tag=one"), /E_NODE_TRANSPORT/);
});
test("explicit TLS obfuscation host is preserved", () => {
  assert.match(direct("shadowsocks=a.example:443, obfs=tls, obfs-host=tls.example, tag=one"), /obfs-host=tls.example/);
});
test("tag containing a fake option cannot affect TLS handling", () => {
  assert.match(direct("anytls=a.example:443, password=test, tag=one, tls-host=not-an-option"), /tls-host=a.example, tag=one, tls-host=not-an-option$/);
});
test("two-hop alias resolves in same resource", () => {
  assert.match(direct("trojan=a.example:443, tag=one", "alias=/a.example/mid.example\nalias=/mid.example/b.example"), /^trojan=b.example:/);
});
test("case and trailing-dot normalization retains original identity", () => {
  assert.match(direct("anytls=A.Example.:443, tag=one", "alias=/a.example/B.Example."), /^anytls=b.example:443, tls-host=A.Example\./);
});
test("exact alias does not match subdomain", () => {
  const n = "trojan=sub.a.example:443, tag=one";
  assert.equal(direct(n), n);
});
test("duplicate identical alias is harmless", () => {
  assert.match(direct("trojan=a.example:443, tag=one", "alias=/a.example/b.example\nalias=/A.EXAMPLE/B.EXAMPLE"), /^trojan=b.example:/);
});
test("loop errors contain no private input", () => error(resource(profile("trojan=a.example:443, password=secret-value, tag=one", "alias=/a.example/b.example\nalias=/b.example/a.example")), "E_ALIAS_CYCLE"));
test("conflicting source is rejected", () => error(resource(profile("trojan=a.example:443, tag=one", "alias=/a.example/b.example\nalias=/a.example/c.example")), "E_ALIAS_CONFLICT"));
test("wildcard source is not broadened", () => error(resource(profile("trojan=a.example:443, tag=one", "alias=/*.example/b.example")), "E_ALIAS_FORMAT"));
test("IP target is not substituted", () => error(resource(profile("trojan=a.example:443, tag=one", "alias=/a.example/192.0.2.1")), "E_ALIAS_FORMAT"));
test("URL target is rejected", () => error(resource(profile("trojan=a.example:443, tag=one", "alias=/a.example/https://b.example")), "E_ALIAS_FORMAT"));
test("chain length limit is enforced", () => {
  const aliases = Array.from({length:17}, (_,i) => "alias=/n"+i+".example/n"+(i+1)+".example").join("\n");
  error(resource(profile("trojan=n0.example:443, tag=one", aliases)), "E_ALIAS_CHAIN");
});
test("exactly 16 hops is supported", () => {
  const aliases = Array.from({length:16}, (_,i) => "alias=/n"+i+".example/n"+(i+1)+".example").join("\n");
  assert.match(direct("trojan=n0.example:443, tag=one",aliases), /^trojan=n16.example:/);
});
test("subscription scopes never share aliases", () => {
  const n = "shadowsocks=a.example:8388, method=aes-128-gcm, password=test, tag=one";
  assert.match(direct(n), /^shadowsocks=b.example:/);
  const c = adapter.prepare(resource(n));
  assert.equal(adapter.transform(c,n),n);
});
test("unrelated section alias text is ignored", () => {
  const c = adapter.prepare(resource("[filter_local]\nalias=/a.example/b.example"));
  assert.equal(c.aliases.size,0);
});
test("non-server resources bypass adapter", () => {
  const c = adapter.prepare(resource("[dns]\nalias=invalid", "filter"));
  assert.equal(c.aliases.size,0); assert.equal(c.error,null);
});
test("remote-only full profile is not imported as partial nodes", () => {
  error(resource("[server_remote]\nhttps://subscription.example/nodes, tag=test\n[dns]\nalias=/a.example/b.example"), "E_NESTED_RESOURCE");
});
test("unsupported alias output modes fail explicitly", () => {
  error(resource(profile("trojan=a.example:443, tag=one"), "server", "#relay=Proxy"), "E_ALIAS_MODE");
});
test("IPv4 and IPv6 endpoints stay intact", () => {
  const lines = "trojan=192.0.2.1:443, tag=ip\ntrojan=[2001:db8::1]:443, tag=ip6";
  assert.equal(direct(lines),lines);
});
test("invalid aliased port is rejected", () => assert.throws(() => direct("trojan=a.example:0, tag=one"),/E_NODE_FORMAT/));
test("duplicate identity fields reject entire result", () => {
  const c=adapter.prepare(resource(profile("trojan=a.example:443, tag=one")));
  assert.throws(() => adapter.transform(c,"trojan=a.example:443, tag=good\ntrojan=a.example:443, tls-host=x.example, tls-host=y.example, tag=bad"),/E_NODE_FIELDS/);
});
test("anonymous QX full profile passes complete upstream pipeline", () => {
  const r=output(resource(profile("anytls=a.example:443, password=test, tls-host=identity.example, tls-verification=true, tag=US-One")));
  assert.match(r.content,/anytls=b.example:443/); assert.match(r.content,/tls-host=identity.example/);assert.match(r.content,/tls-verification=true/);
});
test("explicit certificate override still wins", () => {
  const r=output(resource(profile("trojan=a.example:443, password=test, tls-verification=true, tag=US-One"),"server","#cert=-1"));
  assert.match(r.content,/tls-verification=false/);
});
test("rename and filter parameters continue working", () => {
  const nodes="trojan=a.example:443, password=test, tag=US-One\ntrojan=a.example:443, password=test, tag=JP-Two";
  const r=output(resource(profile(nodes),"server","#in=US&rename=US@America"));
  assert.match(r.content,/tag=America-One/); assert(!r.content.includes("JP-Two")); assert.match(r.content,/trojan=b.example:/);
});
test("upstream metadata is preserved on alias resource", () => {
  const input=resource(profile("trojan=a.example:443, password=test, tag=one"));
  const before=run(original,input).outputs.at(-1),after=output(input);
  assert.deepEqual(after.info,before.info);
});
test("UA retry remains a retry", () => {
  const result=output(resource(profile("trojan=a.example:443, password=test, tag=one"),"server","#UA=1"));
  assert(result.retry); assert.equal(result.content,undefined);
});
const clash="hosts:\n  a.example: b.example\ndns:\n  use-hosts: true\nproxies:\n  - {name: US-One, type: trojan, server: a.example, port: 443, password: test, sni: identity.example, skip-cert-verify: false}\n";
test("confirmed enabled Clash domain hosts use same alias adapter", () => {
  const r=output(resource(clash)); assert.match(r.content,/trojan=b.example:/);assert.match(r.content,/tls-host=identity.example/);
});
test("disabled Clash hosts preserve upstream behavior", () => {
  const input=resource(clash.replace("use-hosts: true","use-hosts: false"));
  assert.deepEqual(run(generated,input).outputs,run(original,input).outputs);
});
test("Clash IP hosts preserve upstream behavior", () => {
  const input=resource(clash.replace("a.example: b.example","a.example: 192.0.2.1"));
  assert.deepEqual(run(generated,input).outputs,run(original,input).outputs);
});
test("Clash IP list hosts preserve upstream behavior", () => {
  const input=resource(clash.replace("a.example: b.example","a.example: [192.0.2.1, 192.0.2.2]"));
  assert.deepEqual(run(generated,input).outputs,run(original,input).outputs);
});
test("Clash URL host value is not mistaken for IPv6", () => error(resource(clash.replace("a.example: b.example","a.example: https://b.example")),"E_ALIAS_FORMAT"));
test("Clash JSON hosts follow enabled metadata contract", () => {
  const text=JSON.stringify({hosts:{"a.example":"b.example"},dns:{"use-hosts":true},proxies:[{name:"one",type:"trojan",server:"a.example",port:443,password:"test",sni:"identity.example"}]});
  const r=output(resource(text));assert.match(r.content,/trojan=b.example:/);assert.match(r.content,/tls-host=identity.example/);
});
test("malformed enabled Clash alias fails without content", () => error(resource(clash.replace("a.example: b.example","a.example: [b.example]")),"E_ALIAS_FORMAT"));
test("Clash alias cycle fails without partial output", () => error(resource(clash.replace("a.example: b.example","a.example: b.example\n  b.example: a.example")),"E_ALIAS_CYCLE"));
test("Clash conversion error cannot import partial alias result", () => {
  error(resource(clash.replace("server: a.example", "server: null")),"E_NODE_CONVERSION");
});
test("empty selection cannot return upstream placeholder node", () => {
  error(resource(profile("trojan=a.example:443, password=test, tag=US-One"),"server","#in=NO-MATCH"),"E_NODE_FORMAT");
});
test("mixed unsupported Clash protocol rejects partial subscription", () => {
  const extra="  - {name: unsupported, type: hysteria2, server: a.example, port: 443, password: test}\n";
  error(resource(clash+extra),"E_NODE_TRANSPORT");
});
test("older AnyTLS client rejects partial subscription", () => {
  const input=resource(clash+"  - {name: anytls, type: anytls, server: a.example, port: 443, password: test, sni: identity.example}\n");
  const r=run(generated,input,913); assert.equal(r.outputs.length,1);assert.match(r.outputs[0].error,/E_NODE_TRANSPORT/);
});
test("raw-data console logging is disabled", () => {
  assert.equal(run(generated,resource(clash)).logs.length,0);
});
test("mapped Clash credentials and flags survive lossy YAML repair", () => {
  const text=clash.replace("password: test", () => "password: 'test$`value'").replace("skip-cert-verify: false", "skip-cert-verify: false, tfo: true, udp: true");
  const r=output(resource(text));assert.match(r.content,/password=test\$`value/);assert.match(r.content,/fast-open=true/);assert.match(r.content,/udp-relay=true/);assert.match(r.content,/tls-verification=true/);
});
for (const input of [
  resource("trojan=a.example:443, password=test, tag=one"),
  resource("host-suffix, example.com, direct", "filter"),
  resource("^https://example\\.com/ad url reject", "rewrite"),
  resource(clash.replace("hosts:\n  a.example: b.example\ndns:\n  use-hosts: true\n", ""))
]) {
  test("no-alias golden compatibility: " + input.type + " " + input.content.split("\n")[0].split("=")[0].slice(0,24), () => {
    assert.deepEqual(run(generated,input).outputs,run(original,input).outputs);
  });
}
test("parser helper UI remains exposed", () => {
  const r=run(generated,resource("trojan=a.example:443, password=test, tag=one"));
  assert.equal(typeof r.context.$parser.hashSchema,"function");
  assert(r.context.$parser.hashSchema());
});
// Opt-in private samples: never print assertion operands, notifications, or logs.
if (process.env.HFGJ_PRIVATE_SAMPLES_ROOT) {
  const privateRoot=path.resolve(process.env.HFGJ_PRIVATE_SAMPLES_ROOT);
  for (const name of ["amy","ytoo","linkcube"]) {
    test("private QX sample: " + name, () => {
      try {
        const text=fs.readFileSync(path.join(privateRoot,"QuantumultX/quantumult-"+name+".conf"),"utf8");
        const c=adapter.prepare(resource(text)); assert(!c.error); assert(c.aliases.size);
        const before=run(original,resource(text)).outputs.at(-1),after=output(resource(text)); assert(!after.error);
        const decoded=Buffer.from(before.content,"base64").toString("utf8");
        const oldNodes=decoded.split("\n"),newNodes=after.content.split("\n");
        assert.equal(newNodes.length,oldNodes.length);
        const mappings=new Map([...text.matchAll(/^\s*alias\s*=\s*\/([^/\s]+)\/([^/\s]+)\s*$/gm)].map(m=>[m[1].toLowerCase(),m[2].toLowerCase()]));
        oldNodes.forEach((line,i)=>{
          const endpoint=/^([^=]+=\s*)([^:\s]+):([0-9]+)/.exec(line);assert(endpoint);
          let host=endpoint[2].toLowerCase();for(let j=0;mappings.has(host)&&j<16;j++)host=mappings.get(host);
          const expected=line.replace(endpoint[0],endpoint[1]+host+":"+endpoint[3]);
          assert.equal(newNodes[i],expected);
        });
        assert.equal(run(generated,resource(text)).logs.length,0);
      } catch (_) { throw new Error("static sample check failed; details suppressed"); }
    });
  }
  for (const name of ["amy","ytoo","lc","tag"]) {
    test("private Clash sample: " + name, () => {
      try {
        const file=path.join(privateRoot,"clash/provider/"+name+".yaml");
        const text=fs.readFileSync(file,"utf8");
        const config=JSON.parse(execFileSync("python3",["-c","import yaml,json,sys; print(json.dumps(yaml.safe_load(open(sys.argv[1]).read())))",file],{encoding:"utf8",maxBuffer:8*1024*1024}));
        const c=adapter.prepare(resource(text)); adapter.acceptClash(c,config); assert(c.aliases.size);
        const before=run(original,resource(text)).outputs.at(-1),after=output(resource(text)); assert(!after.error);
        const decoded=Buffer.from(before.content,"base64").toString("utf8");
        const newNodes=after.content.split("\n");assert.equal(newNodes.length,config.proxies.length);assert.equal(newNodes.length,decoded.split("\n").length);
        newNodes.forEach((line,i)=>{
          const source=config.proxies[i],endpoint=/^([^=]+)=([^:]+):([0-9]+)/.exec(line);assert(endpoint);
          let host=source.server;for(let j=0;config.hosts[host]&&j<16;j++)host=config.hosts[host];
          assert.equal(endpoint[2],host);assert.equal(Number(endpoint[3]),source.port);
          const fields=new Map(line.split(/,\s*tag=/)[0].split(",").slice(1).map(f=>{const at=f.indexOf("=");return[f.slice(0,at).trim(),f.slice(at+1).trim()];}));
          assert.equal(fields.get("password"),source.password);
          if(source.type==="ss") {
            assert.equal(fields.get("method"),source.cipher);
            if(source["plugin-opts"])assert.equal(fields.get("obfs-host"),source["plugin-opts"].host);
          } else {
            assert.equal(fields.get("tls-host"),source.sni||source.server);
            if(typeof source["skip-cert-verify"]==="boolean")assert.equal(fields.get("tls-verification"),String(!source["skip-cert-verify"]));
          }
          if(typeof source.tfo==="boolean")assert.equal(fields.get("fast-open"),String(source.tfo));
          if(typeof source.udp==="boolean")assert.equal(fields.get("udp-relay"),String(source.udp));
        });
        assert.equal(run(generated,resource(text)).logs.length,0);
      } catch (_) { throw new Error("static sample check failed; details suppressed"); }
    });
  }
  test("private TAG current format preserves documented boundary", () => {
    try {
      const text=fs.readFileSync(path.join(privateRoot,"QuantumultX/quantumult-tag.conf"),"utf8");
      const c=adapter.prepare(resource(text));
      if (/^\[Proxy\]\s*$/m.test(text)) {
        assert.equal(c.error,null);assert.equal(c.aliases.size,0);
        const r=run(generated,resource(text));
        assert.deepEqual(r.outputs,run(original,resource(text)).outputs);
        const last=r.outputs.at(-1);assert(last && !last.error && last.content);
        const nodes=Buffer.from(last.content,"base64").toString("utf8").split("\n").filter(Boolean);
        assert.equal(nodes.length,221);assert.equal(r.logs.length,0);
      } else assert.equal(c.error,"E_NESTED_RESOURCE");
    } catch (_) { throw new Error("static sample check failed; details suppressed"); }
  });
}
process.stdout.write("Passed " + passed + " checks" + (process.exitCode ? " (failures above)" : "") + "\n");
