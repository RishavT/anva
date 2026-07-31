const navigationToggle = document.querySelector("[data-nav-toggle]");
const navigation = document.querySelector("[data-navigation]");

if (navigationToggle && navigation) {
  navigationToggle.addEventListener("click", () => {
    const open = navigationToggle.getAttribute("aria-expanded") !== "true";
    navigationToggle.setAttribute("aria-expanded", String(open));
    navigation.dataset.open = String(open);
  });

  navigation.addEventListener("click", (event) => {
    if (event.target.closest("a") && window.matchMedia("(max-width: 56rem)").matches) {
      navigationToggle.setAttribute("aria-expanded", "false");
      navigation.dataset.open = "false";
    }
  });
}

const errorSummary = document.querySelector("[data-error-summary]");
if (errorSummary) {
  errorSummary.focus();
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && navigationToggle && navigation?.dataset.open === "true") {
    navigationToggle.setAttribute("aria-expanded", "false");
    navigation.dataset.open = "false";
    navigationToggle.focus();
  }
});
