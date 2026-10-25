export type ClientSessionMetadata = {
  user_agent: string | null;
  browser_name: string | null;
  browser_version: string | null;
  os_name: string | null;
  os_version: string | null;
  device_type: "DESKTOP" | "MOBILE" | "TABLET" | "UNKNOWN";
};

type BrandVersion = { brand:string; version:string };
type UserAgentDataLike = {
  brands?: BrandVersion[];
  mobile?: boolean;
  platform?: string;
  getHighEntropyValues?: (hints:string[]) => Promise<Record<string, unknown>>;
};

function firstMatch(pattern:RegExp, value:string) {
  return pattern.exec(value)?.[1] || null;
}

function fallbackBrowser(userAgent:string) {
  const patterns:Array<[string,RegExp]> = [
    ["Microsoft Edge", /(?:Edg|EdgiOS|EdgA)\/([\d.]+)/i],
    ["Opera", /(?:OPR|Opera)\/([\d.]+)/i],
    ["Firefox", /(?:Firefox|FxiOS)\/([\d.]+)/i],
    ["Chrome", /(?:Chrome|CriOS)\/([\d.]+)/i],
    ["Safari", /Version\/([\d.]+).*Safari\//i],
  ];
  for (const [name,pattern] of patterns) {
    const version=firstMatch(pattern,userAgent);
    if (version) return { name, version };
  }
  return { name:null, version:null };
}

function fallbackOs(userAgent:string) {
  if (/Windows NT/i.test(userAgent)) {
    const nt=firstMatch(/Windows NT ([\d.]+)/i,userAgent);
    const versions:Record<string,string>={"10.0":"10/11","6.3":"8.1","6.2":"8","6.1":"7"};
    return { name:"Windows", version:(nt && versions[nt]) || nt };
  }
  if (/Android/i.test(userAgent)) return { name:"Android", version:firstMatch(/Android ([\d.]+)/i,userAgent) };
  if (/iPhone|iPad|iPod/i.test(userAgent)) {
    const version=firstMatch(/OS ([\d_]+)/i,userAgent);
    return { name:"iOS/iPadOS", version:version?.replaceAll("_", ".") || null };
  }
  if (/Mac OS X/i.test(userAgent)) {
    const version=firstMatch(/Mac OS X ([\d_]+)/i,userAgent);
    return { name:"macOS", version:version?.replaceAll("_", ".") || null };
  }
  if (/CrOS/i.test(userAgent)) return { name:"ChromeOS", version:firstMatch(/CrOS [^ ]+ ([\d.]+)/i,userAgent) };
  if (/Linux/i.test(userAgent)) return { name:"Linux", version:null };
  return { name:null, version:null };
}

function preferredBrand(brands:BrandVersion[]) {
  const useful=brands.filter(item=>!/Not[ _]?A[; ]?Brand/i.test(item.brand));
  const preferences=["Microsoft Edge","Opera","Google Chrome","Chromium"];
  for (const wanted of preferences) {
    const found=useful.find(item=>item.brand.toLowerCase()===wanted.toLowerCase());
    if (found) return { name:wanted === "Google Chrome" ? "Chrome" : wanted, version:found.version || null };
  }
  const first=useful[0];
  return first ? { name:first.brand, version:first.version || null } : { name:null, version:null };
}

function normalizePlatform(platform:string|null|undefined) {
  const value=(platform||"").trim();
  if (!value) return null;
  if (/win/i.test(value)) return "Windows";
  if (/mac/i.test(value)) return "macOS";
  if (/android/i.test(value)) return "Android";
  if (/ios|iphone|ipad/i.test(value)) return "iOS/iPadOS";
  if (/chrome/i.test(value)) return "ChromeOS";
  if (/linux/i.test(value)) return "Linux";
  return value;
}

export async function collectClientSessionMetadata(): Promise<ClientSessionMetadata> {
  const userAgent=navigator.userAgent || "";
  const nav=navigator as Navigator & { userAgentData?:UserAgentDataLike };
  const uaData=nav.userAgentData;
  let high:Record<string,unknown>={};
  if (uaData?.getHighEntropyValues) {
    try {
      high=await uaData.getHighEntropyValues(["platform","platformVersion","fullVersionList"]);
    } catch { high={}; }
  }

  const fullBrands=Array.isArray(high.fullVersionList) ? high.fullVersionList as BrandVersion[] : (uaData?.brands || []);
  const brand=preferredBrand(fullBrands);
  const fallback= fallbackBrowser(userAgent);
  const fallbackOperatingSystem=fallbackOs(userAgent);
  const osName=normalizePlatform((high.platform as string | undefined) || uaData?.platform || navigator.platform) || fallbackOperatingSystem.name;
  const platformVersion=typeof high.platformVersion === "string" && high.platformVersion ? high.platformVersion : null;

  const tablet=/iPad|Tablet/i.test(userAgent);
  const mobile=Boolean(uaData?.mobile) || /Mobile|iPhone|Android/i.test(userAgent);
  const device_type:ClientSessionMetadata["device_type"] = tablet ? "TABLET" : mobile ? "MOBILE" : "DESKTOP";

  return {
    user_agent:userAgent || null,
    browser_name:brand.name || fallback.name,
    browser_version:brand.version || fallback.version,
    os_name:osName,
    os_version:fallbackOperatingSystem.version || platformVersion,
    device_type,
  };
}
