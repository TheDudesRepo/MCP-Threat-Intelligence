import { describe, expect, it } from "vitest";
import {
  detectIndicatorType,
  parseIndicator,
  refangIndicator,
} from "../src/lib/indicators";

describe("indicator refanging", () => {
  it("refangs common domain and URL patterns", () => {
    expect(refangIndicator("evil[.]example")).toBe("evil.example");
    expect(refangIndicator("hxxps[:]//evil[.]example/path")).toBe(
      "https://evil.example/path",
    );
  });

  it("refangs IPv4 indicators", () => {
    expect(refangIndicator("1[.]2[.]3[.]4")).toBe("1.2.3.4");
  });
});

describe("indicator type detection", () => {
  it("detects file hashes", () => {
    expect(
      detectIndicatorType(
        "44d88612fea8a8f36de82e1278abb02f",
      ),
    ).toBe("file_hash");
  });

  it("detects IPs, domains, and URLs", () => {
    expect(detectIndicatorType("8.8.8.8")).toBe("ip");
    expect(detectIndicatorType("example[.]com")).toBe("domain");
    expect(detectIndicatorType("hxxp://example[.]com/a")).toBe("url");
  });

  it("preserves URL hostname for pivots", () => {
    expect(parseIndicator("hxxps://Sub.Example[.]com/login").hostname).toBe(
      "sub.example.com",
    );
  });
});

