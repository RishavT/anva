const navigation = document.querySelector("[data-navigation]");

if (navigation) {
  if (window.matchMedia("(max-width: 56rem)").matches) {
    navigation.open = false;
  }
  navigation.addEventListener("click", (event) => {
    if (event.target.closest("a") && window.matchMedia("(max-width: 56rem)").matches) {
      navigation.open = false;
    }
  });
}

const errorSummary = document.querySelector("[data-error-summary]");
if (errorSummary) {
  errorSummary.focus();
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && navigation?.open) {
    navigation.open = false;
    navigation.querySelector("summary")?.focus();
  }
});
