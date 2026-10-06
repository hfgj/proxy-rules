"""Build an offline parser from a verified upstream snapshot and the alias adapter."""
from pathlib import Path
import hashlib
import json

BASE = Path(__file__).resolve().parent
OUTPUT = BASE.parent / "resource-parser-hfgj.js"


def build() -> str:
    metadata = json.loads((BASE / "upstream/metadata.json").read_text())
    raw = (BASE / "upstream/resource-parser.js").read_bytes()
    if hashlib.sha256(raw).hexdigest() != metadata["sha256"]:
        raise RuntimeError("上游解析器摘要不符，拒绝构建")
    upstream = raw.decode("utf-8")
    hook = "  const yaml = new YAML()"
    if upstream.count(hook) != 1:
        raise RuntimeError("Clash 元数据接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, hook + ";\n"
                                "  if (/^\\s*hosts\\s*:/m.test(cnt) || /\\\"hosts\\\"\\s*:/.test(cnt)) {\n"
                                "    try {\n"
                                "      HFGJAlias.acceptClash(hfgjAliasContext, JCheck(cnt) === 0 ? yaml.parse(cnt) : JSON.parse(cnt));\n"
                                "    } catch (err) {\n"
                                "      hfgjAliasContext.failed = err.hfgjCode || 'E_ALIAS_FORMAT';\n"
                                "      throw HFGJAlias.failure(hfgjAliasContext.failed);\n"
                                "    }\n"
                                "  }")
    hook = "      node = Pudp0 != 0 ? XUDP(node,Pudp0) : node"
    if upstream.count(hook) != 1:
        raise RuntimeError("Clash 节点保护接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "      node = HFGJAlias.protectClashNode(hfgjAliasContext,\n"
                                "        hfgjAliasContext.clashConfig ? hfgjAliasContext.clashConfig.proxies[i] : bb[i], node);\n" + hook)
    hook = '      total = PRelay==""? Base64.encode(total) : ServerRelay(total.split("\\n"),PRelay)'
    if upstream.count(hook) != 1:
        raise RuntimeError("节点输出接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "      total = HFGJAlias.transform(hfgjAliasContext, total);\n" + hook)
    hook = "function QX_TLS(cnt,Pcert0,PTls13) {"
    if upstream.count(hook) != 1:
        raise RuntimeError("TLS 参数接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, hook + "\n"
                                "  if (!PcertMatch && HFGJAlias.isAliasedNode(hfgjAliasContext, cnt)) Pcert0 = '';\n")
    hook = "      } else { // not support type\n        PNS = PNS+1"
    if upstream.count(hook) != 1:
        raise RuntimeError("不支持节点接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "      } else { // not support type\n"
                                     "        if (hfgjAliasContext.aliases.size) {\n"
                                     "          hfgjAliasContext.failed = 'E_NODE_TRANSPORT';\n"
                                     "          throw HFGJAlias.failure('E_NODE_TRANSPORT');\n"
                                     "        }\n"
                                     "        PNS = PNS+1")
    hook = "      total = errornode"
    if upstream.count(hook) != 1:
        raise RuntimeError("空筛选结果接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "      if (hfgjAliasContext.aliases.size) throw HFGJAlias.failure('E_NODE_FORMAT');\n" + hook)
    hook = '    } catch (err) {\n      if(Perror == 0) {\n      $notify("❌ 解析出现错误"'
    if upstream.count(hook) != 1:
        raise RuntimeError("节点输出错误接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "    } catch (err) {\n"
                                     "      if (hfgjAliasContext.aliases.size || hfgjAliasContext.failed) {\n"
                                     "        hfgjAliasContext.failed = err.hfgjCode || 'E_ALIAS_INTERNAL';\n"
                                     "        throw err;\n"
                                     "      }\n"
                                     '      if(Perror == 0) {\n      $notify("❌ 解析出现错误"')
    hook = "    }catch (e) {\n      $notify(`⚠️该节点解析错误, 暂时已忽略处理`"
    if upstream.count(hook) != 1:
        raise RuntimeError("Clash 错误接入点变化，需重新审查上游")
    upstream = upstream.replace(hook, "    }catch (e) {\n"
                                     "      if (hfgjAliasContext.aliases.size) {\n"
                                     "        hfgjAliasContext.failed = e.hfgjCode || 'E_NODE_CONVERSION';\n"
                                     "        throw HFGJAlias.failure(hfgjAliasContext.failed);\n"
                                     "      }\n"
                                     "      $notify(`⚠️该节点解析错误, 暂时已忽略处理`")
    # Keep the upstream snapshot untouched; disable its raw-data logging in the build.
    upstream = upstream.replace("console.log(", "HFGJAlias.quietLog(")
    # Redirect generated upstream call sites without assigning the host API.
    if "$done(" not in upstream:
        raise RuntimeError("上游完成回调接入点变化，需重新审查上游")
    upstream = upstream.replace("$done(", "hfgjCaptureDone(")
    adapter = (BASE / "hfgj-alias.js").read_text()
    prelude = """
var hfgjAliasContext = HFGJAlias.prepare($resource);
var hfgjNativeDone = $done;
var hfgjPendingResults = [];
function hfgjCaptureDone(payload) { hfgjPendingResults.push(payload); }
if (hfgjAliasContext.error) {
  hfgjNativeDone({error: HFGJAlias.failure(hfgjAliasContext.error).message});
} else {
  try {
"""
    suffix = """
  } catch (err) {
    if (!hfgjAliasContext.aliases.size && !hfgjAliasContext.failed) throw err;
    hfgjAliasContext.failed = err.hfgjCode || 'E_ALIAS_INTERNAL';
  }
  if (hfgjAliasContext.failed) {
    hfgjNativeDone({error: HFGJAlias.failure(hfgjAliasContext.failed).message});
  } else if (hfgjAliasContext.aliases.size) {
    var hfgjFinalResult = hfgjPendingResults[hfgjPendingResults.length - 1];
    if (!hfgjFinalResult || (!hfgjFinalResult.retry && !hfgjFinalResult.error && !hfgjFinalResult.content)) {
      hfgjNativeDone({error: HFGJAlias.failure('E_NODE_FORMAT').message});
    } else hfgjNativeDone(hfgjFinalResult);
  } else {
    hfgjPendingResults.forEach(function (payload) { hfgjNativeDone(payload); });
  }
}
"""
    header = "// HFGJ alias adapter v1.1. Upstream commit: " + metadata["commit"] + "\n"
    return header + adapter + prelude + upstream + suffix


if __name__ == "__main__":
    OUTPUT.write_text(build(), encoding="utf-8")
    print("HFGJ 解析器已从固定上游快照离线构建")
