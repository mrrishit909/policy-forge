// Fonts load only in the standalone site; an embedding host keeps its own fonts and the
// stylesheet falls back to system sans and monospace stacks.
import "@fontsource-variable/atkinson-hyperlegible-next";
import "@fontsource-variable/atkinson-hyperlegible-mono";
import { mount } from "./index";

const el = document.getElementById("app");
if (el) {
  el.removeAttribute("data-boot");
  mount(el, { basePath: import.meta.env.BASE_URL });
}
