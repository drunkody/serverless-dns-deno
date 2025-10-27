import { assertEquals } from "https://deno.land/std@0.220.0/assert/mod.ts";
import { CNAMEInjector } from "./cname-injector.js";

Deno.test("CNAME Injector - Exact Match", () => {
  const injector = new CNAMEInjector();
  injector.rules = {
    "usher.ttvnw.net": {
      target: "proxy.example.com",
      ipv4: "1.2.3.4"
    }
  };
  injector.enabled = true;

  const result = injector.getCNAME("usher.ttvnw.net");
  assertEquals(result.target, "proxy.example.com");
});

Deno.test("CNAME Injector - Wildcard Single Level", () => {
  const injector = new CNAMEInjector();
  injector.rules = {
    "*.ttvnw.net": {
      target: "proxy.example.com",
      ipv4: "1.2.3.4"
    }
  };
  injector.enabled = true;

  const result = injector.getCNAME("video-weaver.ttvnw.net");
  assertEquals(result.target, "proxy.example.com");
});

Deno.test("CNAME Injector - Wildcard Multi Level", () => {
  const injector = new CNAMEInjector();
  injector.rules = {
    "*.ttvnw.net": {
      target: "proxy.example.com",
      ipv4: "1.2.3.4"
    }
  };
  injector.enabled = true;

  const result = injector.getCNAME("a.b.c.ttvnw.net");
  assertEquals(result.target, "proxy.example.com");
});

Deno.test("CNAME Injector - No Match", () => {
  const injector = new CNAMEInjector();
  injector.rules = {
    "*.ttvnw.net": {
      target: "proxy.example.com",
      ipv4: "1.2.3.4"
    }
  };
  injector.enabled = true;

  const result = injector.getCNAME("google.com");
  assertEquals(result, null);
});

Deno.test("CNAME Injector - Build A Response", () => {
  const injector = new CNAMEInjector();

  const originalPacket = {
    id: 1234,
    flag_rd: true,
    questions: [{
      name: "usher.ttvnw.net",
      type: "A"
    }]
  };

  const config = {
    target: "proxy.example.com",
    ipv4: "1.2.3.4"
  };

  const response = injector.buildCNAMEResponse(
    originalPacket,
    "usher.ttvnw.net",
    "proxy.example.com",
    "A",
    config
  );

  assertEquals(response.answers.length, 2);
  assertEquals(response.answers[0].type, "CNAME");
  assertEquals(response.answers[0].data, "proxy.example.com");
  assertEquals(response.answers[1].type, "A");
  assertEquals(response.answers[1].data, "1.2.3.4");
});

Deno.test("CNAME Injector - Build AAAA Response (no IPv6)", () => {
  const injector = new CNAMEInjector();

  const originalPacket = {
    id: 1234,
    flag_rd: true,
    questions: [{
      name: "usher.ttvnw.net",
      type: "AAAA"
    }]
  };

  const config = {
    target: "proxy.example.com",
    ipv4: "1.2.3.4",
    ipv6: null
  };

  const response = injector.buildCNAMEResponse(
    originalPacket,
    "usher.ttvnw.net",
    "proxy.example.com",
    "AAAA",
    config
  );

  // Should only have CNAME, no AAAA record
  assertEquals(response.answers.length, 1);
  assertEquals(response.answers[0].type, "CNAME");
});

Deno.test("CNAME Injector - Build AAAA Response (with IPv6)", () => {
    const injector = new CNAMEInjector();

    const originalPacket = {
      id: 1234,
      flag_rd: true,
      questions: [{
        name: "usher.ttvnw.net",
        type: "AAAA"
      }]
    };

    const config = {
      target: "proxy.example.com",
      ipv4: "1.2.3.4",
      ipv6: "2001:db8::1"
    };

    const response = injector.buildCNAMEResponse(
      originalPacket,
      "usher.ttvnw.net",
      "proxy.example.com",
      "AAAA",
      config
    );

    assertEquals(response.answers.length, 2);
    assertEquals(response.answers[0].type, "CNAME");
    assertEquals(response.answers[1].type, "AAAA");
    assertEquals(response.answers[1].data, "2001:db8::1");
  });