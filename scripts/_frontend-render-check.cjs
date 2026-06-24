// Frontend render checker (used by scripts/check-frontend-render.sh).
// For each file:// page, at desktop (1280) and mobile (390): assert zero console-errors,
// no horizontal page overflow, and no element overflowing its own box (the "no weird wraps /
// overflow" quality bar). Intended scrollers and the decorative chain crosshair are exempt.
const puppeteer = require("puppeteer-core");

const HELIUM = "/Applications/Helium.app/Contents/MacOS/Helium";
const WIDTHS = [1280, 390];
const INTENDED_SCROLLERS = ["rl-scroll-x", "rl-cmd__body", "rl-ta", "rl-pre"];
const urls = process.argv.slice(2);

(async () => {
  const browser = await puppeteer.launch({
    executablePath: HELIUM,
    headless: true,
    args: ["--no-sandbox", "--hide-scrollbars"],
  });
  let failed = 0;
  for (const url of urls) {
    for (const width of WIDTHS) {
      const page = await browser.newPage();
      const errors = [];
      page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
      page.on("pageerror", (e) => errors.push("pageerror:" + e.message));
      page.on("requestfailed", (r) => { if (!r.url().startsWith("data:")) errors.push("reqfail:" + r.url()); });
      await page.setViewport({ width, height: 900 });
      await page.goto("file://" + url, { waitUntil: "networkidle0" });
      const result = await page.evaluate((ok) => {
        const root = document.documentElement;
        const pageOverflow = root.scrollWidth > root.clientWidth + 1;
        const skip = new Set(["SVG", "RECT", "PATH", "I", "HR", "TEXTAREA"]);
        const over = [];
        document.querySelectorAll("body *").forEach((el) => {
          if (skip.has(el.tagName)) return;
          const cls = typeof el.className === "string" ? el.className.split(" ") : [];
          if (ok.some((c) => cls.includes(c))) return;
          if (cls.includes("rl-chain__node")) return; // crosshair ::after straddles the joint by design
          if (el.scrollWidth > el.clientWidth + 1 && el.clientWidth > 0) {
            const cs = getComputedStyle(el);
            if (cs.overflowX === "visible" || cs.overflowX === "clip") {
              over.push(el.tagName + "." + (cls[0] || ""));
            }
          }
        });
        return { pageOverflow, over: [...new Set(over)] };
      }, INTENDED_SCROLLERS);
      const name = url.split("/").pop() + "@" + width;
      const problems = [];
      if (errors.length) problems.push("console-errors=" + JSON.stringify(errors.slice(0, 3)));
      if (result.pageOverflow) problems.push("page-overflow");
      if (result.over.length) problems.push("element-overflow=" + result.over.join(","));
      if (problems.length) { console.error("FAIL " + name + ": " + problems.join("; ")); failed++; }
      else console.log("ok   " + name);
      await page.close();
    }
  }
  await browser.close();
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error("ERR", e.message); process.exit(2); });
