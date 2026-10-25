import fs from "node:fs";
import path from "node:path";
const root=process.cwd();
const files=[
  "src/pages/LoginPage.tsx",
  "src/components/common/PasswordChangeRequired.tsx",
  "src/components/device/DeviceForm.tsx",
];
const raw=/<(?:button|input|select|textarea)\b/g;
for(const rel of files){
  const text=fs.readFileSync(path.join(root,rel),"utf8");
  const hits=[...text.matchAll(raw)];
  if(hits.length) throw new Error(`${rel} still owns ${hits.length} raw form control(s)`);
}
for(const rel of [
  "src/design-system/primitives/Button/Button.tsx",
  "src/design-system/primitives/Input/Input.tsx",
  "src/design-system/primitives/Select/Select.tsx",
  "src/design-system/primitives/Checkbox/Checkbox.tsx",
  "src/design-system/primitives/Textarea/Textarea.tsx",
]){ if(!fs.existsSync(path.join(root,rel))) throw new Error(`missing primitive: ${rel}`); }
console.log("[PASS] FR6-D2 form primitive migration guard.");
