/**
 * Page-side fill routine. Passed to chrome.scripting.executeScript (popup)
 * and called directly by the content script — so it must stay completely
 * self-contained (no imports/closures) and use native value setters for
 * framework-controlled inputs.
 */
export function autofillIntoPage(
  username: string,
  password: string,
): "ok" | "no-form" {
  const setNativeValue = (el: HTMLInputElement, value: string): void => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    if (desc?.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const inputs = Array.from(
    document.querySelectorAll("input"),
  ) as HTMLInputElement[];
  const usable = (i: HTMLInputElement): boolean =>
    !i.disabled && !i.readOnly && i.type !== "hidden";

  const passEl = inputs.find((i) => usable(i) && i.type === "password");
  if (!passEl && !username) return "no-form";

  const hint = (i: HTMLInputElement): string =>
    `${i.name} ${i.id} ${i.autocomplete ?? ""} ${i.placeholder ?? ""}`.toLowerCase();
  const userEl =
    inputs.find((i) => usable(i) && i.type === "email") ??
    inputs.find((i) => usable(i) && /user|email|login|account/.test(hint(i))) ??
    inputs.find((i) => usable(i) && i.type === "text");

  if (userEl && username) setNativeValue(userEl, username);
  if (passEl && password) setNativeValue(passEl, password);
  return "ok";
}
