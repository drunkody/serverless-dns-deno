/*
 * CNAME Injector Plugin for serverless-dns
 * Returns custom CNAME responses before upstream resolution
 */

import * as dnsutil from "../../commons/dnsutil.js";
import * as util from "../../commons/util.js";
import * as pres from "../plugin-response.js";

export class CNAMEInjector {
  constructor() {
    this.log = util.logger("CNAMEInjector");
    this.enabled = false;
    this.rules = {};
    this.loadConfig();
  }

  async loadConfig() {
    try {
      const module = await import("./cname-rules.json", { assert: { type: "json" } });
      const config = module.default;

      if (!config.rules || typeof config.rules !== 'object') {
        throw new Error("Invalid cname-rules.json: missing 'rules' object");
      }

      this.enabled = config.enabled !== false; // Default to true
      this.rules = config.rules;

      this.log.i("CNAME injector loaded:", Object.keys(this.rules).length, "rules");

    } catch (e) {
      this.log.e("Failed to load CNAME config, injection DISABLED:", e.message);
      this.enabled = false;
      this.rules = {};
    }
  }

  /**
   * @param {{rxid: string, requestDecodedDnsPacket: any, isDnsMsg: boolean}} ctx
   * @returns {Promise<pres.RResp>}
   */
  async exec(ctx) {
    let response = pres.emptyResponse();

    if (!this.enabled) {
      return response;
    }

    if (!ctx.isDnsMsg) {
      this.log.d(ctx.rxid, "not a dns-msg, skipping cname injection");
      return response;
    }

    try {
      const packet = ctx.requestDecodedDnsPacket;

      if (!dnsutil.hasSingleQuestion(packet)) {
        this.log.d(ctx.rxid, "no single question, skipping");
        return response;
      }

      const question = packet.questions[0];
      const queryName = dnsutil.normalizeName(question.name);
      const queryType = question.type;

      this.log.d(ctx.rxid, "checking cname for:", queryName, "type:", queryType);

      const cnameConfig = this.getCNAME(queryName);

      if (cnameConfig) {
        const cnameTarget = cnameConfig.target;
        this.log.i(ctx.rxid, "CNAME match:", queryName, "→", cnameTarget);

        const dnsPacket = this.buildCNAMEResponse(packet, queryName, cnameTarget, queryType, cnameConfig);
        const dnsBuffer = dnsutil.encode(dnsPacket);

        response.data = pres.dnsResponse(dnsPacket, dnsBuffer, null);
        this.log.d(ctx.rxid, "CNAME response built successfully");
      } else {
        this.log.d(ctx.rxid, "no cname match for:", queryName);
      }
    } catch (e) {
      this.log.e(ctx.rxid, "cname injection error", e.stack);
      response = pres.errResponse("CNAMEInjector", e);
    }

    return response;
  }

  /**
   * Match domain against CNAME rules (exact and wildcard)
   */
  getCNAME(domain) {
    // 1. Exact match first (fastest)
    if (this.rules[domain]) {
      return this.rules[domain];
    }

    // 2. Wildcard match
    for (const [pattern, config] of Object.entries(this.rules)) {
      if (!pattern.includes('*')) continue;

      // Convert DNS wildcard pattern to regex
      const regexPattern = '^' + pattern
        .split('.')
        .map(part => part === '*' ? '.+' : part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
        .join('\\.') + '$';

      const regex = new RegExp(regexPattern);

      if (regex.test(domain)) {
        this.log.d("Wildcard match:", pattern, "→", domain);
        return config;
      }
    }

    return null;
  }

  /**
   * Build DNS response packet with CNAME and A/AAAA records
   */
  buildCNAMEResponse(originalPacket, queryName, cnameTarget, queryType, config) {
    const packet = {
      id: originalPacket.id,
      type: "response",
      flags: 384, // Standard query response
      flag_qr: true,
      opcode: "QUERY",
      flag_aa: false, // Not authoritative
      flag_tc: false,
      flag_rd: originalPacket.flag_rd || true,
      flag_ra: true,
      flag_z: false,
      flag_ad: false,
      flag_cd: false,
      rcode: "NOERROR",
      questions: originalPacket.questions,
      answers: [],
      authorities: [],
      additionals: []
    };

    // Always add CNAME
    packet.answers.push({
      name: queryName,
      type: "CNAME",
      ttl: 300,
      class: "IN",
      flush: false,
      data: cnameTarget
    });

    // Add A record only if query type is A and IPv4 is available
    if (queryType === "A" && config.ipv4) {
      packet.answers.push({
        name: cnameTarget,
        type: "A",
        ttl: 300,
        class: "IN",
        flush: false,
        data: config.ipv4
      });
    }

    // Add AAAA record only if query type is AAAA and IPv6 is available
    if (queryType === "AAAA" && config.ipv6) {
      packet.answers.push({
        name: cnameTarget,
        type: "AAAA",
        ttl: 300,
        class: "IN",
        flush: false,
        data: config.ipv6
      });
    }

    return packet;
  }
}